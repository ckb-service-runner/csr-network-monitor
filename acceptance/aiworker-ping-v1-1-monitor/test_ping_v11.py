"""ping-v1-1-monitor: signed check-in timestamps, lag answers, clock_skew, one attestation error table."""
import os
import random

import pytest

from csrmon import config as config_mod, crypto, csrprobe, ping, protocol, store as store_mod
from csrmon.hashing import to_hex
from fakes import block_hash
from fakes_v2 import FakeChainV2

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MON = (0x51).to_bytes(32, "big")
S = 1_792_281_600
TIP = 50_000
VECTOR_SIG = ("0x5d3e78f3647e5152620f510d89ce95f941f29cd23cf89f92574720aaec2d80cd"
              "6349ce6a93f6734e2575556519bab90bb0b9af8271f6418bab178dd0074c65d2")


def sk(n):
    return n.to_bytes(32, "big")


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def make(tmp_path, clock, **extra):
    base = {"probe_interval_s": 600, "probe_jitter_s": 60, "probe_timeout_s": 3, "answer_deadline_s": 60}
    base.update(extra)
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    lines += [f"{k} = {str(v).lower() if isinstance(v, bool) else v}" for k, v in base.items()]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    fc = FakeChainV2(tip=TIP)
    p = csrprobe.CsrProber(st, fc, c, MON, salt=b"salt", clock=clock, rng=random.Random(3))
    return p, st, c, fc


def checkin(n, ts=None, *, sig=True, peer=None, bad_sig=False):
    peer = peer or f"QmPeer{n}"
    body = {"peer_id": peer, "service_pubkey": pk(n),
            "binding_sig": ping.sign(sk(n), ping.binding_message(peer, pk(n), "testnet")),
            "network": "testnet", "csr_version": "0.9.0"}
    if sig:
        body["ts"] = S if ts is None else ts
        signer = sk(n + 1) if bad_sig else sk(n)
        body["checkin_sig"] = ping.sign(signer, ping.checkin_message(peer, pk(n), "testnet", body["ts"]))
    return body


def test_checkin_message_vector():
    m = ping.checkin_message("QmVectorPeer", pk(7), "testnet", S)
    assert m == f"CSR-CHECKIN-v1\nQmVectorPeer\n{pk(7)}\ntestnet\n{S}"
    assert ping.sign(sk(7), m) == VECTOR_SIG


def test_fresh_checkin_is_accepted(tmp_path):
    p, *_ = make(tmp_path, Clock(S + 10))
    status, body = p.handle_checkin(checkin(1), "203.0.113.5")
    assert status == 200 and "challenge" in body


def test_stale_or_replayed_checkin_is_refused(tmp_path):
    clock = Clock(S + 10)
    p, *_ = make(tmp_path, clock)
    assert p.handle_checkin(checkin(1, ts=S - 61), "203.0.113.5") == (400, {"error": "stale_checkin"})
    assert p.handle_checkin(checkin(1, ts=S + 71), "203.0.113.5") == (400, {"error": "stale_checkin"})
    assert p.handle_checkin(checkin(2), "203.0.113.5")[0] == 200
    clock.t = S + 11
    assert p.handle_checkin(checkin(2), "203.0.113.5") == (400, {"error": "replay"})


def test_bad_checkin_signature(tmp_path):
    p, *_ = make(tmp_path, Clock(S))
    assert p.handle_checkin(checkin(1, bad_sig=True), "203.0.113.5") == (401, {"error": "bad_signature"})


def test_unsigned_checkin_never_costs_a_slot(tmp_path):
    clock = Clock(S + 5)
    p, st, _, _ = make(tmp_path, clock)
    # The runner exists (seen before) and checks in without a signature (v1 runner or a replayed binding).
    assert p.handle_checkin(checkin(3, sig=False), "203.0.113.5")[0] == 200
    rid = protocol.runner_id(crypto.pubkey_from_secret(sk(3)))
    if st.get_runner(rid) is None:
        st.upsert_runner(rid, service_pubkey=pk(3), peer_id="QmPeer3", p2p_pubkey="", reg_outpoint="",
                         mode="outbound", endpoint="", p2p_port=0, ranking_opt_in=True, now=S - 86400)
    clock.t = S + 200
    expired = p._expire_open(S + 200)
    assert all(r.get("failure_reason") != "no_answer" for r in expired)
    assert not st.has_probe(rid, csrprobe.slot_of(S, 600))


def test_signed_checkin_without_answer_is_a_miss(tmp_path):
    clock = Clock(S + 5)
    p, st, _, _ = make(tmp_path, clock)
    rid = protocol.runner_id(crypto.pubkey_from_secret(sk(4)))
    st.upsert_runner(rid, service_pubkey=pk(4), peer_id="QmPeer4", p2p_pubkey="", reg_outpoint="",
                     mode="outbound", endpoint="", p2p_port=0, ranking_opt_in=True, now=S - 86400)
    assert p.handle_checkin(checkin(4, ts=S + 5), "203.0.113.5")[0] == 200
    expired = p._expire_open(S + 200)
    assert any(r.get("failure_reason") == "no_answer" for r in expired)


def test_signature_can_be_required(tmp_path):
    p, *_ = make(tmp_path, Clock(S), require_checkin_sig=True)
    assert p.handle_checkin(checkin(1, sig=False), "203.0.113.5") == (400, {"error": "checkin_sig_required"})


def _answer(height, tip, block_hash_at_height):
    ch = ping.make_challenge(MON, height=height, issued_at=S, nonce=b"\x07" * 32)
    body = ping.make_answer(sk(7), ch, peer_id="QmPeer7", network="testnet", csr_version="0.9.0",
                            node_version="0.200.0", r2_state="Syncing", tip_number=tip, tip_hash=block_hash(tip),
                            block_hash_at_height=block_hash_at_height, uptime_s=100, ping_mode="inbound")
    return ch, body


def test_lagging_runner_is_reachable_but_not_in_sync(tmp_path):
    _, _, _, fc = make(tmp_path, Clock(S))
    ch, body = _answer(TIP - 5, TIP - 30, "")
    r = csrprobe.evaluate_answer(ch, body, chain=fc, network="testnet", elapsed_s=1, deadline_s=60,
                                 sync_threshold=10)
    assert r["result"] == "ok", r
    assert r["in_sync"] is False and r["lag"] == 30


def test_empty_block_hash_needs_a_tip_below_the_height(tmp_path):
    _, _, _, fc = make(tmp_path, Clock(S))
    ch, body = _answer(TIP - 50, TIP - 2, "")
    r = csrprobe.evaluate_answer(ch, body, chain=fc, network="testnet", elapsed_s=1, deadline_s=60,
                                 sync_threshold=10)
    assert r["result"] == "fail" and r["failure_reason"] == "wrong_block_hash", r


def test_reject_reasons():
    assert csrprobe.reject_reason(400, b'{"error":"clock_skew"}') == "clock_skew"
    assert csrprobe.reject_reason(400, b"height above tip") == "rejected_400"
    assert csrprobe.reject_reason(403, b'{"error":"bad_monitor_signature"}') == "bad_monitor_key"
    assert csrprobe.reject_reason(418, b"") == "bad_status"


def test_protocol_doc_points_to_one_attest_table():
    t = open(os.path.join(ROOT, "docs", "PROTOCOL.md")).read()
    assert "CSR-CHECKIN-v1" in t and "checkin_sig" in t and "clock_skew" in t
    assert "monitor-public-api.md" in t
    assert "wrong_owner" not in t
