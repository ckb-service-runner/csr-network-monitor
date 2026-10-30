"""node-identity-monitor: P2P-key identity proofs (D6 A) and the daily check over the monitor's own node (D12 A)."""
import json
import os
import random

import pytest

from csrmon import api as api_mod, config as config_mod, crypto, csrprobe, p2p, ping, protocol, scoring
from csrmon import store as store_mod
from csrmon.hashing import to_hex
from fakes import block_hash
from fakes_v2 import FakeChainV2, peer_entry

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MON = (0x51).to_bytes(32, "big")
S = 1_792_281_600
TIP = 50_000
VECTORS = [
    ("01" * 32, "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
     "Qmecbv6CRqPqSyZUvQ8SQErHYAbq4f2Pucq8ofs2MsdZnG"),
    ("07" * 32, "02989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f",
     "QmS7sXpV62pY1jHiAkiVkftGxJvimJZTLdLuzerj7yafdS"),
    ("42" * 32, "0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c",
     "QmZdgEgD3Gc5y6DcejPXiy6r9VVbu6Vf3jNVcnUCJ5iKmp"),
]
SERVICE = (9).to_bytes(32, "big")
SERVICE_PK = to_hex(crypto.pubkey_from_secret(SERVICE))
P2P_SIG = ("0x5d7a192e210313cf1e33abef3505f216bf473b367520941251dbf0809088e31d"
           "543c7af4ceb44e2d77858816790e3fada41567f727b3c1c040f10e679e9b2ac9")


def make(tmp_path, **extra):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"', "rate_limit_per_min = 1000"]
    lines += [f"{k} = {json.dumps(v)}" for k, v in extra.items()]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    fc = FakeChainV2(tip=TIP)
    pr = csrprobe.CsrProber(st, fc, c, MON, salt=b"salt", clock=lambda: S, rng=random.Random(3))
    a = api_mod.Api(st, c, MON, prober=pr, chain=fc, clock=lambda: S)
    rid = protocol.runner_id(crypto.pubkey_from_secret(SERVICE))
    st.upsert_runner(rid, service_pubkey=SERVICE_PK, peer_id=VECTORS[1][2], p2p_pubkey="", reg_outpoint="",
                     mode="outbound", endpoint="", p2p_port=0, ranking_opt_in=True, now=S - 30 * 86400)
    return {"c": c, "st": st, "fc": fc, "api": a, "rid": rid}


def proof(*, p2p_hex="07" * 32, peer=None, ts=S, service=SERVICE, tamper=False):
    p2p_sk = bytes.fromhex(p2p_hex)
    p2p_pk = to_hex(crypto.pubkey_from_secret(p2p_sk))
    peer = peer or p2p.peer_id_from_pubkey(crypto.pubkey_from_secret(p2p_sk))
    m = p2p.identity_message(peer, SERVICE_PK, "testnet", ts)
    out = {"peer_id": peer, "service_pubkey": SERVICE_PK, "network": "testnet", "ts": ts,
           "p2p_pubkey": p2p_pk, "p2p_sig": ping.sign(p2p_sk, m), "service_sig": ping.sign(service, m)}
    if tamper:
        out["ts"] = ts + 1
    return out


def post(env, body):
    status, _, data = env["api"].handle("POST", "/v1/identity", {}, json.dumps(body).encode(), "203.0.113.4")
    return status, json.loads(data)


def test_peer_id_derivation():
    for _, pk, peer in VECTORS:
        assert p2p.peer_id_from_pubkey(bytes.fromhex(pk)) == peer


def test_identity_message_and_vector():
    m = p2p.identity_message(VECTORS[1][2], SERVICE_PK, "testnet", S)
    assert m == f"CSR-NODE-IDENTITY-v1\n{VECTORS[1][2]}\n{SERVICE_PK}\ntestnet\n{S}"
    assert ping.sign(bytes.fromhex("07" * 32), m) == P2P_SIG


def test_valid_proof_is_stored(tmp_path):
    env = make(tmp_path)
    assert post(env, proof()) == (200, {"ok": True})
    r = env["st"].get_runner(env["rid"])
    assert r["p2p_pubkey"] == "0x" + VECTORS[1][1]
    assert r["identity_proven_at"] == S


def test_proof_must_derive_the_peer_id(tmp_path):
    env = make(tmp_path)
    status, body = post(env, proof(peer=VECTORS[0][2]))
    assert status == 403 and body["error"] == "peer_mismatch"


def test_bad_or_stale_proofs(tmp_path):
    env = make(tmp_path)
    assert post(env, proof(tamper=True))[0] == 401
    assert post(env, proof(service=(10).to_bytes(32, "big")))[0] == 401
    assert post(env, proof(ts=S - 301)) == (400, {"error": "stale"})
    assert post(env, {"peer_id": "x"})[0] == 400


def test_proven_peer_marks_other_claimants(tmp_path):
    env = make(tmp_path)
    other_sk = (11).to_bytes(32, "big")
    other = protocol.runner_id(crypto.pubkey_from_secret(other_sk))
    env["st"].upsert_runner(other, service_pubkey=to_hex(crypto.pubkey_from_secret(other_sk)),
                            peer_id=VECTORS[1][2], p2p_pubkey="", reg_outpoint="", mode="outbound", endpoint="",
                            p2p_port=0, ranking_opt_in=True, now=S - 86400)
    assert post(env, proof())[0] == 200
    assert "identity_mismatch" in env["st"].get_runner(other)["flags"]
    assert "identity_mismatch" not in env["st"].get_runner(env["rid"])["flags"]


def test_identity_gate():
    assert scoring.identity_ok({"identity_proven_at": None}, require=False, now=S)
    assert not scoring.identity_ok({"identity_proven_at": None}, require=True, now=S)
    assert scoring.identity_ok({"identity_proven_at": S - 6 * 86400}, require=True, now=S)
    assert not scoring.identity_ok({"identity_proven_at": S - 8 * 86400}, require=True, now=S)


def _peer(node_id, number, hsh):
    e = peer_entry(node_id, ["/ip4/198.51.100.9/tcp/8115"])
    e["sync_state"] = {"best_known_header_number": hex(number), "best_known_header_hash": hsh}
    return e


def test_evaluate_peer():
    fc = FakeChainV2(tip=TIP)
    peers = [_peer("QmA", TIP - 2, block_hash(TIP - 2)), _peer("QmB", TIP - 40, block_hash(TIP - 40)),
             _peer("QmC", TIP - 1, "0x" + "ee" * 32), _peer("QmD", TIP + 1, "0x" + "aa" * 32)]
    ev = lambda pid: p2p.evaluate_peer(peers, pid, chain=fc, sync_threshold=10)
    assert ev("QmA") == "ok"
    assert ev("QmB") == "behind"
    assert ev("QmC") == "wrong_chain"
    assert ev("QmD") == "ok", "a peer slightly ahead of the monitor is fine"
    assert ev("QmZ") == "not_connected"


def test_daily_check_survives_node_errors(tmp_path):
    env = make(tmp_path, p2p_interval_s=86400)

    class Broken(FakeChainV2):
        def get_peers(self):
            raise RuntimeError("node down")

    sched = p2p.P2PScheduler(env["st"], Broken(tip=TIP), env["c"], clock=lambda: S + 86399)
    out = sched.run_due(S + 86399)
    assert out and all(r["result"] == "error" for r in out)
    assert env["st"].last_p2p_check(env["rid"])["result"] == "error", "the error is recorded, so it is not retried at once"


def test_daily_check_records_the_peer_state(tmp_path):
    env = make(tmp_path, p2p_interval_s=86400)
    env["fc"].peers = [_peer(VECTORS[1][2], TIP - 1, block_hash(TIP - 1))]
    sched = p2p.P2PScheduler(env["st"], env["fc"], env["c"], clock=lambda: S + 86399)
    out = sched.run_due(S + 86399)
    assert [r["result"] for r in out] == ["ok"]


def test_monitor_publishes_its_p2p_address(tmp_path):
    addr = "/ip4/203.0.113.7/tcp/8115/p2p/" + VECTORS[2][2]
    env = make(tmp_path, p2p_public_address=addr)
    status, _, data = env["api"].handle("GET", "/v1/monitor", {}, b"", "10.0.0.1")
    assert status == 200 and json.loads(data)["p2p_address"] == addr


def test_helper_command_is_gone():
    fields = set(config_mod.Config.__dataclass_fields__)
    assert "p2p_check_cmd" not in fields
    proto = open(os.path.join(ROOT, "docs", "PROTOCOL.md")).read()
    assert "/v1/identity" in proto and "CSR-NODE-IDENTITY-v1" in proto and "p2p_address" in proto


# Integration (Oct 2026): a runner on the monitor's own node never shows in its get_peers.
class _OwnNode(FakeChainV2):
    def __init__(self, own, **kw):
        super().__init__(**kw)
        self.own = own

    def local_node_id(self):
        return self.own


def test_runner_on_the_monitors_own_node_counts_when_proven(tmp_path):
    env = make(tmp_path, p2p_interval_s=86400)
    assert post(env, proof())[0] == 200
    fc = _OwnNode(VECTORS[1][2], tip=TIP)
    sched = p2p.P2PScheduler(env["st"], fc, env["c"], clock=lambda: S + 86399)
    assert [r["result"] for r in sched.run_due(S + 86399)] == ["ok"]


def test_claiming_the_monitors_node_id_without_proof_is_not_enough(tmp_path):
    env = make(tmp_path, p2p_interval_s=86400)
    fc = _OwnNode(VECTORS[1][2], tip=TIP)
    sched = p2p.P2PScheduler(env["st"], fc, env["c"], clock=lambda: S + 86399)
    out = sched.run_due(S + 86399)
    assert [(r["result"], r["reason"]) for r in out] == [("fail", "not_connected")]
