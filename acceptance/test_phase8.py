"""Phase 8 acceptance: public REST API, rate limits, privacy, HTTP server.
(v2 version: the v1 check-in routes are removed.)"""
import base64
import json
import random
import sqlite3
import time
import urllib.request

import pytest

from csrmon import api as api_mod, scoring, prober as prober_mod, protocol, crypto
from csrmon import store as store_mod, config as config_mod
from fakes import FakeChain, block_hash

MON = (11).to_bytes(32, "big")
NOW = 1_792_281_600 + 12 * 3600     # 2026-10-18 12:00 UTC
TODAY = "2026-10-18"
SECRET_IP = "203.0.113.77"


def sk(n):
    return n.to_bytes(32, "big")


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def rid_of(n):
    return protocol.runner_id(crypto.pubkey_from_secret(sk(n)))


def add(st, n, age_days=40, mode="pull", status=None, country="DE", asn=3320):
    pk = crypto.pubkey_from_secret(sk(n))
    rid = protocol.runner_id(pk)
    st.upsert_runner(rid, service_pubkey="0x" + pk.hex(),
                     peer_id=protocol.peer_id_from_pubkey(crypto.pubkey_from_secret(sk(100 + n))),
                     p2p_pubkey="0x02", reg_outpoint="0x" + "ab" * 32 + ":1", mode=mode,
                     endpoint=f"https://{SECRET_IP}:8443" if mode == "pull" else "",
                     p2p_port=8115, ranking_opt_in=True, now=NOW - age_days * 86400)
    st.record_probe(rid, ts=NOW - 7200, slot=1, mode=mode, result="ok", lag=1, in_sync=True,
                    peers_out=8, csr_version="0.1.0", ckb_version="0.203.0",
                    ip_hash="0x" + "99" * 32, country=country, asn=asn)
    if status:
        st.set_status(rid, status)
    return rid


def put_days(db, rid, days=30, ok=140):
    con = sqlite3.connect(db)
    for d in range(days):
        con.execute("insert or replace into daily_stats(runner_id, day, probes_total, probes_ok,"
                    " in_sync, p2p_total, p2p_ok, median_lag, median_peers, score)"
                    " values (?,?,?,?,?,?,?,?,?,null)",
                    (rid, store_mod.add_days(TODAY, -d), 144, ok, ok, 1, 1, 1, 8))
    con.commit()
    con.close()


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"',
             "probe_timeout_s = 5", 'trusted_proxies = ["127.0.0.1"]']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    cfg = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(cfg.db_path)
    st.set_meta("monitor_start", str(NOW - 50 * 86400))
    clock = Clock(NOW)
    fc = FakeChain(tip=80_000)
    pr = prober_mod.Prober(st, fc, cfg, MON, salt=b"s", clock=clock, rng=random.Random(1))
    api = api_mod.Api(st, cfg, MON, prober=pr, chain=fc, clock=clock)
    return {"cfg": cfg, "st": st, "clock": clock, "api": api, "chain": fc, "prober": pr}


IPS = iter(f"10.9.{a}.{b}" for a in range(256) for b in range(256))


def get(env, path, ip=None, headers=None):
    status, hdrs, body = env["api"].handle("GET", path, headers or {}, b"", ip or next(IPS))
    return status, hdrs, json.loads(body) if body else None


def post(env, path, obj, ip="5.1.2.3", raw=None):
    data = raw if raw is not None else json.dumps(obj).encode()
    status, hdrs, body = env["api"].handle("POST", path, {"Content-Type": "application/json"},
                                           data, ip)
    return status, json.loads(body)


def test_monitor_endpoint(env):
    status, hdrs, body = get(env, "/v1/monitor")
    assert status == 200
    assert hdrs["Content-Type"].startswith("application/json")
    assert hdrs["Access-Control-Allow-Origin"] == "*"
    assert body["pubkey"] == "0x" + crypto.pubkey_from_secret(MON).hex()
    assert body["version"] == "0.1.0" and body["score_formula"] == "score_v1"
    assert body["network"] == "testnet" and body["public_url"] == "https://m.example"
    assert body["tip"] == {"number": 80_000, "hash": block_hash(80_000)}
    assert body["paused"] is False and body["stat_cell_type_hash"] is None
    env["prober"].paused = True
    env["chain"].fail = True
    body = get(env, "/v1/monitor")[2]
    assert body["paused"] is True and body["tip"] is None


def test_routing_errors(env):
    assert get(env, "/v1/mainnet/summary")[:3:2] == (404, {"error": "unknown_network"})
    assert get(env, "/v1/devnet/runners")[0] == 404
    assert get(env, "/v1/testnet/nothing")[2] == {"error": "not_found"}
    assert get(env, "/v2/x")[0] == 404
    status, _, body = env["api"].handle("DELETE", "/v1/monitor", {}, b"", "1.1.1.1")
    assert status == 405
    status, _, body = env["api"].handle("GET", "/v1/testnet/checkin", {}, b"", "1.1.1.1")
    assert status == 404          # v2: the v1 check-in routes are gone


def test_summary_matches_scoring(env):
    for n in range(1, 4):
        put_days(env["cfg"].db_path, add(env["st"], n))
    status, _, body = get(env, "/v1/testnet/summary")
    assert status == 200
    assert body == scoring.network_summary(env["st"], TODAY, env["cfg"])
    assert body["runner_count"] == 3


def test_runners_paging(env):
    ids = []
    for n in range(1, 8):
        rid = add(env["st"], n)
        put_days(env["cfg"].db_path, rid, ok=100 + n)
        ids.append(rid)
    status, _, full = get(env, "/v1/testnet/runners?limit=500")
    assert status == 200 and full["network"] == "testnet" and full["score_formula"] == "score_v1"
    assert full["date"] == TODAY and full["next_cursor"] is None
    assert [i["runner_id"] for i in full["items"]] == list(reversed(ids))
    assert [i["rank"] for i in full["items"]] == list(range(1, 8))
    item = full["items"][0]
    assert set(item) == {"runner_id", "rank", "score", "provisional", "status", "flags",
                         "a7", "a30", "a365", "country", "region", "asn", "asn_peers"}
    assert item["country"] == "DE" and item["asn"] == 3320 and item["asn_peers"] == 6
    seen, cursor = [], None
    while True:
        q = "/v1/testnet/runners?limit=3" + (f"&cursor={cursor}" if cursor else "")
        page = get(env, q)[2]
        assert len(page["items"]) <= 3
        seen += [i["runner_id"] for i in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == [i["runner_id"] for i in full["items"]]
    assert len(get(env, "/v1/testnet/runners")[2]["items"]) == 7   # default limit 50
    for bad in ("limit=0", "limit=501", "limit=abc"):
        assert get(env, "/v1/testnet/runners?" + bad)[2] == {"error": "bad_limit"}
    assert get(env, "/v1/testnet/runners?cursor=%%%")[2] == {"error": "bad_cursor"}


def test_runner_detail(env):
    rid = add(env["st"], 1)
    put_days(env["cfg"].db_path, rid)
    env["st"].record_p2p_check(rid, ts=NOW - 100, heights=[1], served=1, latency_ms=5,
                               peer_id_seen="x", result="ok")
    status, _, d = get(env, f"/v1/testnet/runners/{rid}")
    assert status == 200
    assert d["runner_id"] == rid and d["rank"] == 1 and d["provisional"] is False
    assert d["status"] == "active" and d["flags"] == []
    assert set(d["metrics"]) == {"a7", "a30", "a365", "s30", "f30", "t", "p", "median_lag_30"}
    assert d["score"] == scoring.runner_metrics(env["st"], rid, TODAY)["score"]
    assert d["first_seen"] == NOW - 40 * 86400 and d["first_seen_day"] == "2026-09-08"
    assert d["last_seen"] == NOW - 7200
    reg = d["registration"]
    assert reg["mode"] == "pull" and reg["has_endpoint"] is True
    assert reg["service_pubkey"] == "0x" + crypto.pubkey_from_secret(sk(1)).hex()
    assert reg["peer_id"].startswith("Qm") and reg["reg_outpoint"] == "0x" + "ab" * 32 + ":1"
    assert d["country"] == "DE" and d["region"] == "EU" and d["asn"] == 3320 and d["asn_peers"] == 0
    assert d["csr_version"] == "0.1.0" and d["ckb_version"] == "0.203.0"
    assert d["last_probe"] == {"ts": NOW - 7200, "result": "ok", "failure_reason": None}
    assert d["last_p2p_check"] == {"ts": NOW - 100, "result": "ok"}
    assert get(env, f"/v1/testnet/runners/{rid.upper().replace('0X', '0x')}")[0] == 200
    assert get(env, "/v1/testnet/runners/0x" + "00" * 32)[2] == {"error": "unknown_runner"}
    env["st"].set_status(rid, "deregistered")
    assert get(env, f"/v1/testnet/runners/{rid}")[0] == 404
    env["api"].invalidate()
    assert get(env, "/v1/testnet/runners")[2]["items"] == []


def test_history(env):
    rid = add(env["st"], 1)       # adds one ok probe at NOW-7200
    st = env["st"]
    st.record_probe(rid, ts=NOW - 7100, slot=2, mode="pull", result="fail", failure_reason="timeout")
    st.record_probe(rid, ts=NOW - 3000, slot=3, mode="pull", result="ok", lag=4, in_sync=True)
    st.record_probe(rid, ts=NOW - 2900, slot=4, mode="pull", result="excluded")
    put_days(env["cfg"].db_path, rid, days=3)
    status, _, h = get(env, f"/v1/testnet/runners/{rid}/history?bucket=hour&from={NOW - 86400}&to={NOW}")
    assert status == 200 and h["runner_id"] == rid and h["bucket"] == "hour"
    assert h["from"] == NOW - 86400 and h["to"] == NOW
    assert h["items"] == [
        {"start": NOW - 7200, "probes_total": 2, "probes_ok": 1, "in_sync": 1, "median_lag": 1},
        {"start": NOW - 3600, "probes_total": 1, "probes_ok": 1, "in_sync": 1, "median_lag": 4},
    ]
    d = get(env, f"/v1/testnet/runners/{rid}/history?bucket=day")[2]
    assert d["from"] == NOW - 7 * 86400 and d["to"] == NOW
    assert [i["day"] for i in d["items"]] == ["2026-10-16", "2026-10-17", "2026-10-18"]
    first = d["items"][0]
    assert first["start"] == store_mod.day_start("2026-10-16")
    assert set(first) == {"start", "day", "probes_total", "probes_ok", "in_sync", "median_lag",
                          "p2p_total", "p2p_ok", "score"}
    assert get(env, f"/v1/testnet/runners/{rid}/history?bucket=week")[2] == {"error": "bad_bucket"}
    assert get(env, f"/v1/testnet/runners/{rid}/history?from=10&to=5")[2] == {"error": "bad_range"}
    assert get(env, f"/v1/testnet/runners/{rid}/history?from=0&to={NOW}")[2] == {"error": "bad_range"}
    assert get(env, "/v1/testnet/runners/0x" + "00" * 32 + "/history")[0] == 404


def test_epochs(env):
    assert get(env, "/v1/testnet/epochs")[2] == {"items": []}
    assert get(env, "/v1/testnet/epochs/1")[2] == {"error": "unknown_epoch"}
    env["st"].save_epoch(1, start=10, end=20, merkle_root="0xaa", data_hex="0x01",
                         summary={"leaves": [], "runner_count": 0})
    env["st"].set_epoch_tx(1, "0xtx")
    assert get(env, "/v1/testnet/epochs")[2] == {"items": [
        {"epoch": 1, "start": 10, "end": 20, "merkle_root": "0xaa", "stat_cell_tx": "0xtx"}]}
    e = get(env, "/v1/testnet/epochs/1")[2]
    assert e["epoch"] == 1 and e["merkle_root"] == "0xaa" and e["stat_cell_tx"] == "0xtx"
    assert e["leaves"] == [] and e["runner_count"] == 0
    assert get(env, "/v1/testnet/epochs/x")[0] == 404


def test_v1_checkin_routes_removed(env):
    # v2: CSR nodes check in at /v1/checkin and /v1/answer (test_v2_api.py)
    for path in ("/v1/testnet/checkin", "/v1/testnet/checkin/response"):
        status, _, _ = env["api"].handle("POST", path, {}, b"{}", "5.1.2.3")
        assert status == 404


def test_rate_limit(env):
    for _ in range(60):
        assert get(env, "/v1/monitor", ip="7.7.7.7")[0] == 200
    status, hdrs, body = get(env, "/v1/monitor", ip="7.7.7.7")
    assert status == 429 and body == {"error": "rate_limited"}
    assert int(hdrs["Retry-After"]) >= 1
    assert get(env, "/v1/monitor", ip="7.7.7.8")[0] == 200
    env["clock"].t += 61
    assert get(env, "/v1/monitor", ip="7.7.7.7")[0] == 200


def test_forwarded_for(env):
    for _ in range(60):
        get(env, "/v1/monitor", ip="127.0.0.1", headers={"X-Forwarded-For": "9.9.9.1, 8.8.8.8"})
    # trusted proxy: the rightmost address is the client
    assert get(env, "/v1/monitor", ip="127.0.0.1", headers={"x-forwarded-for": "8.8.8.8"})[0] == 429
    assert get(env, "/v1/monitor", ip="127.0.0.1", headers={"X-Forwarded-For": "8.8.4.4"})[0] == 200
    # untrusted peer: header ignored
    for _ in range(60):
        get(env, "/v1/monitor", ip="6.6.6.6", headers={"X-Forwarded-For": "1.0.0.1"})
    assert get(env, "/v1/monitor", ip="6.6.6.6", headers={"X-Forwarded-For": "1.0.0.2"})[0] == 429


def test_no_ip_addresses_anywhere(env):
    rid = add(env["st"], 1)
    put_days(env["cfg"].db_path, rid)
    paths = ["/v1/monitor", "/v1/testnet/summary", "/v1/testnet/runners",
             f"/v1/testnet/runners/{rid}", f"/v1/testnet/runners/{rid}/history?bucket=hour",
             f"/v1/testnet/runners/{rid}/history?bucket=day"]
    for p in paths:
        status, hdrs, body = env["api"].handle("GET", p, {}, b"", next(IPS))
        assert status == 200, p
        assert SECRET_IP.encode() not in body, p
        assert b"https://" not in body or p == "/v1/monitor", p


def test_cache(env):
    rid = add(env["st"], 1)
    put_days(env["cfg"].db_path, rid)
    a = get(env, "/v1/testnet/summary")[2]["runner_count"]
    put_days(env["cfg"].db_path, add(env["st"], 2))
    assert get(env, "/v1/testnet/summary")[2]["runner_count"] == a      # cached
    env["clock"].t += 31
    assert get(env, "/v1/testnet/summary")[2]["runner_count"] == a + 1
    put_days(env["cfg"].db_path, add(env["st"], 3))
    env["api"].invalidate()
    assert get(env, "/v1/testnet/summary")[2]["runner_count"] == a + 2


def test_performance_500_runners(env):
    st = env["st"]
    con = sqlite3.connect(env["cfg"].db_path)
    rows, stats = [], []
    for n in range(500):
        rid = "0x" + f"{n:064x}"
        rows.append((rid, "0x02", f"Qm{n}", "0x03", "0x0:0", "pull", "https://x", 0,
                     NOW - 100 * 86400, None, "active", "[]", 1, "DE", "EU", 3320 + n % 40,
                     "0.1.0", "0.203.0"))
        for d in range(30):
            stats.append((rid, store_mod.add_days(TODAY, -d), 144, 140, 130, 1, 1, 1, 8, None))
    con.executemany("insert into runners(runner_id, service_pubkey, peer_id, p2p_pubkey, reg_outpoint,"
                    " mode, endpoint, p2p_port, first_seen, last_seen, status, flags, ranking_opt_in,"
                    " country, region, asn, csr_version, ckb_version)"
                    " values (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
    con.executemany("insert into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                    " p2p_total, p2p_ok, median_lag, median_peers, score)"
                    " values (?,?,?,?,?,?,?,?,?,?)", stats)
    con.commit()
    con.close()
    t0 = time.monotonic()
    assert get(env, "/v1/testnet/runners?limit=500")[0] == 200
    assert time.monotonic() - t0 < 30            # first, uncached computation
    times = []
    for i in range(20):
        path = "/v1/testnet/summary" if i % 2 else "/v1/testnet/runners?limit=100"
        t0 = time.monotonic()
        assert get(env, path)[0] == 200
        times.append(time.monotonic() - t0)
    times.sort()
    assert times[18] < 0.3


def test_http_server(env):
    srv = api_mod.ApiServer(env["api"], "127.0.0.1", 0)
    srv.start()
    try:
        assert srv.port > 0
        with urllib.request.urlopen(f"http://127.0.0.1:{srv.port}/v1/monitor", timeout=5) as r:
            assert r.status == 200
            assert r.headers["Access-Control-Allow-Origin"] == "*"
            assert json.loads(r.read())["network"] == "testnet"
        req = urllib.request.Request(f"http://127.0.0.1:{srv.port}/v1/checkin",
                                     data=b"{}", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
            assert False, "expected HTTP error"
        except urllib.error.HTTPError as e:
            assert e.code == 400
    finally:
        srv.stop()
