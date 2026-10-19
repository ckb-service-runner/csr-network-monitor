"""Map phase 1: snapped coordinates from a city CSV, stored per runner (never per probe)."""
import os
import random
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # acceptance/ (fakes_v2)

from csrmon import geo, store as store_mod, config as config_mod, csrprobe, crypto, protocol  # noqa: E402
from csrmon.hashing import to_hex  # noqa: E402
from fakes_v2 import FakeChainV2  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NOW = 1_792_281_600 + 12 * 3600
MON = (0x51).to_bytes(32, "big")

CITY = (
    "5.1.0.0,5.1.0.255,EU,DE,Berlin,Berlin,52.52,13.40\n"
    '5.1.1.0,5.1.1.255,EU,DE,Berlin,"Berlin, Mitte",52.53,13.38\n'      # same cell as above: merged
    "5.1.2.0,5.1.2.255,EU,DE,Bavaria,Munich,48.14,11.58\n"
    '8.8.8.0,8.8.8.255,NA,US,California,"Mountain View",37.42,-122.08\n'
    "9.9.9.0,9.9.9.255,EU,ZZ,,,0,0\n"                                     # unknown country: skipped
    "10.0.0.0,10.0.0.255,AS,JP,Tokyo,Tokyo,,\n"                          # no coordinates: skipped
    "11.0.0.0,11.0.0.255,AS,JP,Tokyo,Tokyo,x,139.7\n"                    # bad coordinates: skipped
    "2001:db8::,2001:db8::ffff,EU,FR,Ile-de-France,Paris,48.86,2.35\n"
    "garbage line\n"
)


@pytest.fixture
def city_csv(tmp_path):
    p = tmp_path / "city.csv"
    p.write_text(CITY)
    return str(p)


def test_snap():
    assert geo.GRID_DEG == 2
    assert geo.snap(52.52, 13.40) == (53, 13)
    assert geo.snap(48.14, 11.58) == (49, 11)
    assert geo.snap(37.42, -122.08) == (37, -123)
    assert geo.snap(-33.87, 151.21) == (-33, 151)
    assert geo.snap(0, 0) == (1, 1)
    assert geo.snap(-0.5, -0.5) == (-1, -1)
    assert geo.snap(90, 180) == (89, -179)
    assert geo.snap(-90, -180) == (-89, -179)
    for v in geo.snap(12.3, 45.6):
        assert isinstance(v, int)


def test_locate(city_csv):
    db = geo.GeoDB(city_csv=city_csv)
    assert db.locate("5.1.0.7") == (53, 13)
    assert db.locate("5.1.1.200") == (53, 13)
    assert db.locate("5.1.2.1") == (49, 11)
    assert db.locate("8.8.8.8") == (37, -123)
    assert db.locate("2001:db8::42") == (49, 3)
    for ip in ("9.9.9.9", "10.0.0.1", "11.0.0.1", "5.1.3.0", "7.7.7.7", "2001:db9::1", "not-an-ip", ""):
        assert db.locate(ip) is None, ip
    assert db.city_range_count == 4          # Berlin (merged), Munich, Mountain View, Paris
    assert geo.GeoDB().locate("5.1.0.7") is None
    assert geo.GeoDB().city_range_count == 0


def test_lookup_unchanged(tmp_path, city_csv):
    c = tmp_path / "country.csv"
    c.write_text("5.1.0.0,5.1.255.255,DE\n")
    db = geo.GeoDB(str(c), None, city_csv)
    assert db.lookup("5.1.2.3") == {"country": "DE", "region": "EU", "asn": 0, "as_org": ""}
    assert db.locate("5.1.2.3") == (49, 11)


def test_config_key(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "a.toml").write_text("\n".join(lines) + "\n")
    assert config_mod.load_config(str(tmp_path / "a.toml")).geo_city_csv == ""
    (tmp_path / "b.toml").write_text("\n".join(lines + ['geo_city_csv = "/x/city.csv"']) + "\n")
    assert config_mod.load_config(str(tmp_path / "b.toml")).geo_city_csv == "/x/city.csv"
    daemon_src = open(os.path.join(ROOT, "csrmon", "daemon.py"), encoding="utf-8").read()
    assert "geo_city_csv" in daemon_src
    for f in ("config/monitor-testnet.toml", "config/monitor-mainnet.toml"):
        assert "geo_city_csv" in open(os.path.join(ROOT, f), encoding="utf-8").read(), f


def _runner(st, n=1):
    pub = crypto.pubkey_from_secret(n.to_bytes(32, "big"))
    rid = protocol.runner_id(pub)
    st.upsert_runner(rid, service_pubkey=to_hex(pub), peer_id=f"Qm{n}", p2p_pubkey="", reg_outpoint="",
                     mode="inbound", endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=True,
                     now=NOW - 86400)
    return rid


def _cols(path, table):
    con = sqlite3.connect(path)
    try:
        return {r[1] for r in con.execute(f"pragma table_info({table})")}
    finally:
        con.close()


def test_store_location(tmp_path):
    path = str(tmp_path / "t.db")
    st = store_mod.Store(path)
    rid = _runner(st)
    assert st.get_runner(rid)["loc_lat"] is None and st.get_runner(rid)["loc_lon"] is None
    st.record_probe(rid, ts=NOW, slot=1, mode="inbound", result="ok", country="DE", asn=3320,
                    loc_lat=53, loc_lon=13)
    r = st.get_runner(rid)
    assert (r["country"], r["loc_lat"], r["loc_lon"]) == ("DE", 53, 13)
    # no IP information in this probe: location untouched
    st.record_probe(rid, ts=NOW + 600, slot=2, mode="inbound", result="ok")
    assert (st.get_runner(rid)["loc_lat"], st.get_runner(rid)["loc_lon"]) == (53, 13)
    # country known, location unknown: location cleared
    st.record_probe(rid, ts=NOW + 1200, slot=3, mode="inbound", result="ok", country="DE", asn=3320)
    assert (st.get_runner(rid)["loc_lat"], st.get_runner(rid)["loc_lon"]) == (None, None)
    # unknown country never has a location
    st.record_probe(rid, ts=NOW + 1800, slot=4, mode="inbound", result="ok", country="??", asn=0,
                    loc_lat=53, loc_lon=13)
    r = st.get_runner(rid)
    assert (r["country"], r["loc_lat"], r["loc_lon"]) == ("??", None, None)
    assert "loc_lat" not in _cols(path, "probes") and "loc_lon" not in _cols(path, "probes")


def test_store_migration(tmp_path):
    path = str(tmp_path / "old.db")
    con = sqlite3.connect(path)
    con.execute("create table runners(runner_id text primary key, service_pubkey text, peer_id text,"
                " p2p_pubkey text, reg_outpoint text, mode text, endpoint text, p2p_port integer,"
                " first_seen integer, last_seen integer, status text, flags text not null default '[]',"
                " ranking_opt_in integer, country text, region text, asn integer, csr_version text,"
                " ckb_version text)")
    con.execute("insert into runners(runner_id, status, country) values ('0xaa', 'active', 'DE')")
    con.commit()
    con.close()
    st = store_mod.Store(path)
    assert {"loc_lat", "loc_lon"} <= _cols(path, "runners")
    r = st.get_runner("0xaa")
    assert r["country"] == "DE" and r["loc_lat"] is None
    store_mod.Store(path)                    # opening again is fine


class LookupOnlyGeo:
    """An older geo object without locate()."""

    def lookup(self, ip):
        return {"country": "DE", "region": "EU", "asn": 3320, "as_org": ""}


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def _prober(tmp_path, geodb):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/p.db"', f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    pr = csrprobe.CsrProber(st, FakeChainV2(tip=80_000), c, MON, geo=geodb, salt=b"s",
                            clock=Clock(NOW), rng=random.Random(1))
    return st, pr


def test_prober_stores_location(tmp_path, city_csv):
    c = tmp_path / "country.csv"
    c.write_text("5.1.0.0,5.1.255.255,DE\n8.8.8.0,8.8.8.255,US\n")
    st, pr = _prober(tmp_path, geo.GeoDB(str(c), None, city_csv))
    rid = _runner(st)
    pr._record(rid, NOW, "inbound", "ok", None, ip="5.1.2.7")
    r = st.get_runner(rid)
    assert (r["country"], r["loc_lat"], r["loc_lon"]) == ("DE", 49, 11)
    rid2 = _runner(st, 2)
    pr._record(rid2, NOW, "inbound", "ok", None, ip="5.1.9.9")       # country known, no city row
    r2 = st.get_runner(rid2)
    assert (r2["country"], r2["loc_lat"], r2["loc_lon"]) == ("DE", None, None)


def test_prober_with_old_geo_object(tmp_path):
    st, pr = _prober(tmp_path, LookupOnlyGeo())
    rid = _runner(st)
    pr._record(rid, NOW, "inbound", "ok", None, ip="5.1.2.7")
    r = st.get_runner(rid)
    assert (r["country"], r["loc_lat"], r["loc_lon"]) == ("DE", None, None)
