"""v2 Phase 6 acceptance: CSR-compatible endpoints of the API (spec/ping-protocol.md §5 and
spec/monitor-public-api.md of ckb-service-runner)."""
import json
import random
import sqlite3

import pytest

from csrmon import api as api_mod, csrprobe, crypto, protocol, store as store_mod, config as config_mod
from csrmon.hashing import to_hex
from fakes_v2 import FakeChainV2, FakeCSR

MON = (0x51).to_bytes(32, "big")
MON_PK = to_hex(crypto.pubkey_from_secret(MON))
NOW = 1_792_281_600 + 12 * 3600        # 2026-10-18 12:00 UTC
TODAY = "2026-10-18"


def sk(n):
    return n.to_bytes(32, "big")


def rid_of(n):
    return protocol.runner_id(crypto.pubkey_from_secret(sk(n)))


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://monitor-testnet.vericell.net"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    st.set_meta("monitor_start", str(NOW - 60 * 86400))
    clock = Clock(NOW)
    fc = FakeChainV2(tip=80_000)
    pr = csrprobe.CsrProber(st, fc, c, MON, clock=clock, rng=random.Random(2))
    api = api_mod.Api(st, c, MON, prober=pr, chain=fc, clock=clock)
    return {"c": c, "st": st, "clock": clock, "fc": fc, "pr": pr, "api": api}


IPS = iter(f"10.8.{a}.{b}" for a in range(256) for b in range(256))


def call(env, method, path, obj=None, raw=None, ip=None):
    body = raw if raw is not None else (json.dumps(obj).encode() if obj is not None else b"")
    status, hdrs, data = env["api"].handle(method, path, {"Content-Type": "application/json"},
                                           body, ip or next(IPS))
    return status, hdrs, (json.loads(data) if data else None)


def test_checkin_and_answer_over_api(env):
    node = FakeCSR(sk(1), "QmPeer1", env["fc"], MON_PK, clock=env["clock"])
    status, hdrs, body = call(env, "POST", "/v1/checkin", node.checkin_body())
    assert status == 200 and set(body) == {"challenge"}
    assert hdrs["Content-Type"].startswith("application/json")
    code, answer = node.respond(body["challenge"])
    assert code == 200
    status, _, res = call(env, "POST", "/v1/answer", answer)
    assert (status, res) == (200, {"result": "ok"})
    assert env["st"].get_runner(rid_of(1))["mode"] == "outbound"
    # a failing answer
    env["clock"].t += 600
    status, _, body = call(env, "POST", "/v1/checkin", node.checkin_body())
    code, answer = node.respond(body["challenge"])
    answer["answer"]["uptime_s"] = 5            # breaks the signature
    status, _, res = call(env, "POST", "/v1/answer", answer)
    assert (status, res) == (422, {"result": "fail", "failure_reason": "bad_signature"})


def test_checkin_errors(env):
    assert call(env, "POST", "/v1/checkin", raw=b"{nope")[0] == 400
    assert call(env, "POST", "/v1/answer", raw=b"[]")[0] == 400
    assert call(env, "POST", "/v1/checkin", raw=b"x" * 20000)[0] == 413
    assert call(env, "GET", "/v1/checkin")[0] == 405
    assert call(env, "GET", "/v1/answer")[0] == 405
    # the v1 routes are gone
    assert call(env, "POST", "/v1/testnet/checkin", {"a": 1})[0] == 404
    assert call(env, "POST", "/v1/testnet/checkin/response", {"a": 1})[0] == 404
    env["api"].prober = None
    assert call(env, "POST", "/v1/checkin", {"a": 1})[:3:2] == (503, {"error": "unavailable"})


def add_runner(env, n, *, peer, country="DE", age_days=40, ok_days=30, p2p=None, last_probe_ago=600):
    st = env["st"]
    st.upsert_runner(rid_of(n), service_pubkey=to_hex(crypto.pubkey_from_secret(sk(n))), peer_id=peer,
                     p2p_pubkey="", reg_outpoint="", mode="inbound", endpoint="http://1.2.3.4:8131",
                     p2p_port=0, ranking_opt_in=True, now=NOW - age_days * 86400)
    st.record_probe(rid_of(n), ts=NOW - last_probe_ago, slot=n * 1000, mode="inbound", result="ok",
                    lag=1, in_sync=True, country=country, asn=3320, p2p_verified=p2p)
    con = sqlite3.connect(env["c"].db_path)
    for d in range(ok_days):
        con.execute("insert or replace into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                    " p2p_total, p2p_ok, median_lag, median_peers, score) values (?,?,?,?,?,?,?,?,?,null)",
                    (rid_of(n), store_mod.add_days(TODAY, -d), 144, 140 - n, 130, 0, 0, 1, None))
    con.commit()
    con.close()


def test_network_endpoint(env):
    add_runner(env, 1, peer="QmA", country="DE")
    add_runner(env, 2, peer="QmB", country="DE")
    add_runner(env, 3, peer="QmC", country="US", last_probe_ago=7200)     # not reachable now
    add_runner(env, 4, peer="QmD", country=None)
    status, hdrs, body = call(env, "GET", "/v1/network")
    assert status == 200 and hdrs["Access-Control-Allow-Origin"] == "*"
    assert body == {"nodes_total": 4, "nodes_reachable": 3,
                    "countries": [{"code": "DE", "count": 2}, {"code": "US", "count": 1}],
                    "updated_at": NOW}


def test_nodes_endpoint(env):
    add_runner(env, 1, peer="QmA", p2p=True)
    add_runner(env, 2, peer="QmB", p2p=False)
    add_runner(env, 3, peer="QmNew", age_days=2, ok_days=2)              # provisional
    status, _, a = call(env, "GET", "/v1/nodes/QmA")
    assert status == 200
    assert set(a) == {"peer_id", "rank", "of", "availability", "check_type", "attestation",
                      "stake", "last_check_at"}
    assert a["peer_id"] == "QmA" and a["rank"] == 1 and a["of"] == 2
    assert a["availability"] == {"d7": round(139 / 144, 4), "d30": round(139 / 144, 4),
                                 "d365": round(139 / 144, 4)}
    assert a["check_type"] == "peer_connected"
    env["st"].record_p2p_check(rid_of(1), ts=NOW - 47 * 3600, heights=[], served=1, latency_ms=None,
                               peer_id_seen="QmA", result="ok")
    assert call(env, "GET", "/v1/nodes/QmA")[2]["check_type"] == "p2p_verified"
    assert a["attestation"] == {"status": "none", "expiry": None}
    assert a["stake"] == {"status": "none", "capacity_ckb": None, "outpoint": None}
    assert a["last_check_at"] == NOW - 600
    b = call(env, "GET", "/v1/nodes/QmB")[2]
    assert b["rank"] == 2 and b["check_type"] == "challenge_only"
    assert call(env, "GET", "/v1/nodes/Qm%41")[2]["peer_id"] == "QmA"     # URL-decoded
    assert call(env, "GET", "/v1/nodes/QmNew")[:3:2] == (404, {"error": "not_ranked"})
    assert call(env, "GET", "/v1/nodes/QmUnknown")[0] == 404


def test_nodes_attestation_status(env):
    add_runner(env, 1, peer="QmA")
    add_runner(env, 2, peer="QmB")
    env["st"].set_registrations([
        {"peer_id": "QmA", "service_pubkey": "0x02", "expiry_ms": (NOW + 86400) * 1000 + 500, "outpoint": "x"},
        {"peer_id": "QmB", "service_pubkey": "0x02", "expiry_ms": (NOW - 10) * 1000, "outpoint": "y"},
    ])
    assert call(env, "GET", "/v1/nodes/QmA")[2]["attestation"] == {"status": "valid", "expiry": NOW + 86400}
    assert call(env, "GET", "/v1/nodes/QmB")[2]["attestation"] == {"status": "expired", "expiry": NOW - 10}
