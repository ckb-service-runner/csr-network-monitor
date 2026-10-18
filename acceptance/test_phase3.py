"""Phase 3 acceptance: SQLite store and offline geolocation."""
import os
import sqlite3
import stat
import threading

import pytest

from csrmon import store as store_mod, geo
from csrmon.hashing import ckb_blake2b

DAY = 86400
T0 = 1760745600  # 2025-10-18 00:00:00 UTC


def rid(n):
    return "0x" + f"{n:064x}"


def add_runner(s, n, now=T0, **kw):
    args = dict(service_pubkey="0x02" + "11" * 32, peer_id=f"QmPeer{n}",
                p2p_pubkey="0x03" + "22" * 32, reg_outpoint="0x" + "ab" * 32 + ":0",
                mode="pull", endpoint="https://r.example", p2p_port=8115,
                ranking_opt_in=True, now=now)
    args.update(kw)
    return s.upsert_runner(rid(n), **args)


@pytest.fixture
def s(tmp_path):
    st = store_mod.Store(str(tmp_path / "t.db"))
    yield st
    st.close()


def test_day_helpers():
    assert store_mod.day_of(T0) == "2025-10-18"
    assert store_mod.day_of(T0 + DAY - 1) == "2025-10-18"
    assert store_mod.day_start("2025-10-18") == T0
    assert store_mod.add_days("2025-10-18", -30) == "2025-09-18"


def test_schema_and_wal(tmp_path):
    path = str(tmp_path / "t.db")
    st = store_mod.Store(path)
    st.close()
    con = sqlite3.connect(path)
    mode = con.execute("PRAGMA journal_mode").fetchone()[0]
    tables = {r[0] for r in con.execute("select name from sqlite_master where type='table'")}
    con.close()
    assert mode.lower() == "wal"
    assert {"runners", "probes", "p2p_checks", "daily_stats", "epochs", "meta"} <= tables
    store_mod.Store(path).close()  # reopening is fine


def test_upsert_and_get_runner(s):
    assert add_runner(s, 1, now=T0) is True
    r = s.get_runner(rid(1))
    assert r["runner_id"] == rid(1)
    assert r["service_pubkey"] == "0x02" + "11" * 32
    assert r["peer_id"] == "QmPeer1"
    assert r["mode"] == "pull" and r["endpoint"] == "https://r.example"
    assert r["p2p_port"] == 8115
    assert r["first_seen"] == T0 and r["last_seen"] is None
    assert r["status"] == "active" and r["flags"] == [] and r["ranking_opt_in"] is True
    for k in ("country", "region", "asn", "csr_version", "ckb_version", "reg_outpoint", "p2p_pubkey"):
        assert k in r
    assert s.get_runner(rid(99)) is None
    # update keeps first_seen, opt-out changes status
    assert add_runner(s, 1, now=T0 + 500, endpoint="https://new.example", ranking_opt_in=False) is False
    r = s.get_runner(rid(1))
    assert r["first_seen"] == T0 and r["endpoint"] == "https://new.example"
    assert r["status"] == "opted_out" and r["ranking_opt_in"] is False
    add_runner(s, 1, now=T0 + 900)
    assert s.get_runner(rid(1))["status"] == "active"


def test_list_status_flags(s):
    for n in (3, 1, 2):
        add_runner(s, n)
    s.set_status(rid(2), "deregistered")
    assert [r["runner_id"] for r in s.list_runners()] == [rid(1), rid(3)]
    assert [r["runner_id"] for r in s.list_runners(statuses=None)] == [rid(1), rid(2), rid(3)]
    assert [r["runner_id"] for r in s.list_runners(statuses=("deregistered",))] == [rid(2)]
    with pytest.raises(ValueError):
        s.set_status(rid(1), "weird")
    s.set_flag(rid(1), "identity_mismatch", True)
    s.set_flag(rid(1), "bad_binding", True)
    s.set_flag(rid(1), "identity_mismatch", True)
    assert s.get_runner(rid(1))["flags"] == ["bad_binding", "identity_mismatch"]
    s.set_flag(rid(1), "bad_binding", False)
    assert s.get_runner(rid(1))["flags"] == ["identity_mismatch"]


def test_record_probe_and_runner_update(s):
    add_runner(s, 1)
    ok = s.record_probe(rid(1), ts=T0 + 100, slot=1, mode="pull", result="ok", latency_ms=40,
                        tip_number=1000, lag=1, in_sync=True, peers_out=8,
                        csr_version="0.1.0", ckb_version="0.203.0", ip_hash="0xab",
                        country="DE", asn=3320)
    assert ok is True
    assert s.has_probe(rid(1), 1) and not s.has_probe(rid(1), 2)
    # one outcome per slot
    assert s.record_probe(rid(1), ts=T0 + 200, slot=1, mode="pull", result="fail",
                          failure_reason="timeout") is False
    r = s.get_runner(rid(1))
    assert r["last_seen"] == T0 + 100
    assert r["country"] == "DE" and r["region"] == "EU" and r["asn"] == 3320
    assert r["csr_version"] == "0.1.0" and r["ckb_version"] == "0.203.0"
    s.record_probe(rid(1), ts=T0 + 700, slot=2, mode="pull", result="fail", failure_reason="timeout")
    assert s.get_runner(rid(1))["last_seen"] == T0 + 100  # failures do not update last_seen
    rows = s.probes(rid(1))
    assert [p["slot"] for p in rows] == [1, 2]
    p = rows[0]
    assert p["result"] == "ok" and p["in_sync"] is True and p["lag"] == 1 and p["peers_out"] == 8
    assert p["mode"] == "pull" and p["latency_ms"] == 40 and p["ip_hash"] == "0xab"
    assert rows[1]["failure_reason"] == "timeout" and rows[1]["in_sync"] is None
    assert s.last_probe(rid(1))["slot"] == 2
    assert s.last_probe(rid(2)) is None
    assert [p["slot"] for p in s.probes(rid(1), since=T0 + 101)] == [2]
    assert [p["slot"] for p in s.probes(rid(1), until=T0 + 700)] == [1]
    with pytest.raises(ValueError):
        s.record_probe(rid(1), ts=T0, slot=9, mode="pull", result="maybe")


def test_p2p_checks(s):
    add_runner(s, 1)
    s.record_p2p_check(rid(1), ts=T0 + 50, heights=[5, 900], served=2, latency_ms=300,
                       peer_id_seen="QmPeer1", result="ok")
    s.record_p2p_check(rid(1), ts=T0 + 90, heights=[6], served=0, latency_ms=None,
                       peer_id_seen=None, result="error")
    rows = s.p2p_checks(rid(1))
    assert rows[0]["heights"] == [5, 900] and rows[0]["result"] == "ok" and rows[0]["served"] == 2
    assert s.last_p2p_check(rid(1))["ts"] == T0 + 90
    with pytest.raises(ValueError):
        s.record_p2p_check(rid(1), ts=T0, heights=[], served=0, latency_ms=0,
                           peer_id_seen=None, result="bogus")


def test_aggregate_day(s):
    add_runner(s, 1)
    add_runner(s, 2)
    probes = [  # result, in_sync, lag, peers
        ("ok", True, 0, 8), ("ok", True, 2, 6), ("ok", False, 40, 4),
        ("fail", None, None, None), ("excluded", None, None, None),
    ]
    for i, (res, ins, lag, peers) in enumerate(probes):
        s.record_probe(rid(1), ts=T0 + i * 600, slot=i, mode="pull", result=res,
                       in_sync=ins, lag=lag, peers_out=peers)
    s.record_probe(rid(1), ts=T0 + DAY + 5, slot=999, mode="pull", result="ok", in_sync=True, lag=0)
    s.record_p2p_check(rid(1), ts=T0 + 10, heights=[1], served=1, latency_ms=1,
                       peer_id_seen="QmPeer1", result="ok")
    s.record_p2p_check(rid(1), ts=T0 + 20, heights=[1], served=0, latency_ms=1,
                       peer_id_seen=None, result="fail")
    s.record_p2p_check(rid(2), ts=T0 + 30, heights=[1], served=0, latency_ms=1,
                       peer_id_seen=None, result="error")
    assert s.aggregate_day("2025-10-18") == 2
    [d] = s.daily_stats(rid(1), "2025-10-18", "2025-10-18")
    assert d["day"] == "2025-10-18"
    assert d["probes_total"] == 4 and d["probes_ok"] == 3 and d["in_sync"] == 2
    assert d["p2p_total"] == 2 and d["p2p_ok"] == 1
    assert d["median_lag"] == 2 and d["median_peers"] == 6
    assert d["score"] is None
    [d2] = s.daily_stats(rid(2), "2025-10-01", "2025-10-31")
    assert d2["probes_total"] == 0 and d2["p2p_total"] == 1 and d2["p2p_ok"] == 0
    assert d2["median_lag"] is None
    # score survives re-aggregation
    s.set_daily_score(rid(1), "2025-10-18", 77.5)
    s.aggregate_day("2025-10-18")
    assert s.daily_stats(rid(1), "2025-10-18", "2025-10-18")[0]["score"] == 77.5
    s.aggregate_day("2025-10-19")
    assert [d["day"] for d in s.daily_stats(rid(1), "2025-10-01", "2025-10-31")] == \
        ["2025-10-18", "2025-10-19"]


def test_prune(s):
    add_runner(s, 1)
    s.record_probe(rid(1), ts=T0, slot=1, mode="pull", result="ok")
    s.record_probe(rid(1), ts=T0 + 91 * DAY, slot=2, mode="pull", result="ok")
    s.record_p2p_check(rid(1), ts=T0, heights=[1], served=1, latency_ms=1,
                       peer_id_seen="x", result="ok")
    assert s.prune(T0 + 91 * DAY, 90) == 2
    assert [p["slot"] for p in s.probes(rid(1))] == [2]
    assert s.p2p_checks(rid(1)) == []


def test_meta_and_epochs(s):
    assert s.get_meta("monitor_start") is None
    assert s.get_meta("monitor_start", "x") == "x"
    s.set_meta("monitor_start", "123")
    s.set_meta("monitor_start", "124")
    assert s.get_meta("monitor_start") == "124"
    s.save_epoch(1, start=10, end=20, merkle_root="0xaa", data_hex="0x01", summary={"k": [1]})
    s.save_epoch(2, start=20, end=30, merkle_root="0xbb", data_hex="0x02", summary={})
    e = s.get_epoch(1)
    assert e == {"epoch": 1, "start": 10, "end": 20, "merkle_root": "0xaa",
                 "data_hex": "0x01", "stat_cell_tx": None, "summary": {"k": [1]}}
    s.set_epoch_tx(1, "0xtx")
    assert s.get_epoch(1)["stat_cell_tx"] == "0xtx"
    assert [e["epoch"] for e in s.list_epochs()] == [1, 2]
    assert s.get_epoch(3) is None


def test_store_is_thread_safe(s):
    add_runner(s, 1)

    def work(base):
        for i in range(100):
            s.record_probe(rid(1), ts=T0 + base + i, slot=base + i, mode="push", result="ok")

    threads = [threading.Thread(target=work, args=(k * 1000,)) for k in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(s.probes(rid(1))) == 800


# ---------- geo ----------

def test_region_for():
    assert geo.region_for("DE") == "EU"
    assert geo.region_for("US") == "NA"
    assert geo.region_for("BR") == "SA"
    assert geo.region_for("JP") == "AS"
    assert geo.region_for("AU") == "OC"
    assert geo.region_for("NG") == "AF"
    assert geo.region_for("AQ") == "AN"
    assert geo.region_for("CN") == "AS"
    assert geo.region_for("de") == "EU"
    assert geo.region_for("??") == "??"
    assert geo.region_for(None) == "??"
    assert geo.region_for("XX") == "??"


def test_region_table_is_broad():
    assert len(geo.COUNTRY_REGION) >= 240
    assert set(geo.COUNTRY_REGION.values()) == {"AF", "AN", "AS", "EU", "NA", "OC", "SA"}


def test_geodb_lookup(tmp_path):
    c = tmp_path / "country.csv"
    c.write_text("1.0.0.0,1.0.0.255,AU\n"
                 "5.1.0.0,5.1.255.255,DE\n"
                 "8.8.8.0,8.8.8.255,US\n"
                 "9.9.9.0,9.9.9.255,ZZ\n"
                 "2001:db8::,2001:db8::ffff,FR\n")
    a = tmp_path / "asn.csv"
    a.write_text('5.1.0.0,5.1.255.255,3320,"Deutsche Telekom, AG"\n'
                 "8.8.8.0,8.8.8.255,15169,Google LLC\n"
                 "2001:db8::,2001:db8::ffff,64500,Doc Net\n")
    db = geo.GeoDB(str(c), str(a))
    assert db.lookup("5.1.2.3") == {"country": "DE", "region": "EU", "asn": 3320,
                                    "as_org": "Deutsche Telekom, AG"}
    assert db.lookup("1.0.0.255") == {"country": "AU", "region": "OC", "asn": 0, "as_org": ""}
    assert db.lookup("8.8.8.8")["asn"] == 15169
    assert db.lookup("2001:db8::42") == {"country": "FR", "region": "EU", "asn": 64500,
                                         "as_org": "Doc Net"}
    unknown = {"country": "??", "region": "??", "asn": 0, "as_org": ""}
    assert db.lookup("9.9.9.9") == unknown          # ZZ means unknown
    assert db.lookup("7.7.7.7") == unknown          # between ranges
    assert db.lookup("not-an-ip") == unknown
    empty = geo.GeoDB()
    assert empty.lookup("5.1.2.3") == unknown


def test_ip_hash_and_salt(tmp_path):
    salt = geo.load_or_create_salt(str(tmp_path / "s" / "salt"))
    assert len(salt) == 32
    assert stat.S_IMODE(os.stat(tmp_path / "s" / "salt").st_mode) == 0o600
    assert geo.load_or_create_salt(str(tmp_path / "s" / "salt")) == salt
    h = geo.ip_hash("5.1.2.3", salt)
    assert h == "0x" + ckb_blake2b(salt + b"5.1.2.3").hex()
    assert "5.1.2.3" not in h
    assert geo.ip_hash("5.1.2.3", b"other") != h
