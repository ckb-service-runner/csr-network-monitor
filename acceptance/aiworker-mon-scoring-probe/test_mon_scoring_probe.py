"""mon-scoring-probe: tip challenge (D13 A), score_v1 frozen without P (D11 B, D18 A), flags and labels."""
import os
import random

import pytest

from csrmon import config as config_mod, crypto, csrprobe, ping, protocol, scoring, store as store_mod
from csrmon.hashing import to_hex
from fakes import block_hash
from fakes_v2 import FakeChainV2

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MON = (0x51).to_bytes(32, "big")
S = 1_792_281_600
TIP = 50_000


def sk(n):
    return n.to_bytes(32, "big")


def make(tmp_path, **extra):
    base = {"probe_interval_s": 600, "probe_jitter_s": 60, "probe_timeout_s": 3, "answer_deadline_s": 60,
            "sync_threshold": 10}
    base.update(extra)
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    lines += [f"{k} = {v}" for k, v in base.items()]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    fc = FakeChainV2(tip=TIP)
    p = csrprobe.CsrProber(st, fc, c, MON, salt=b"salt", clock=lambda: S, rng=random.Random(3))
    return p, st, c, fc


def answer(fc, *, height, tip, tip_hash=None, n=7):
    ch = ping.make_challenge(MON, height=height, issued_at=S, nonce=b"\x07" * 32)
    body = ping.make_answer(sk(n), ch, peer_id=f"QmPeer{n}", network="testnet", csr_version="0.9.0",
                            node_version="0.200.0", r2_state="Synced", tip_number=tip,
                            tip_hash=tip_hash if tip_hash is not None else block_hash(tip),
                            block_hash_at_height=block_hash(height), uptime_s=100, ping_mode="inbound")
    return ch, body


def evaluate(fc, ch, body):
    return csrprobe.evaluate_answer(ch, body, chain=fc, network="testnet", elapsed_s=1, deadline_s=60,
                                    sync_threshold=10)


# ---- D13 A: tip challenge as specified ----

def test_correct_tip_passes(tmp_path):
    _, _, _, fc = make(tmp_path)
    r = evaluate(fc, *answer(fc, height=TIP - 50, tip=TIP - 2))
    assert r["result"] == "ok", r
    assert r["lag"] == 2 and r["in_sync"] is True


def test_wrong_tip_hash_fails(tmp_path):
    _, _, _, fc = make(tmp_path)
    r = evaluate(fc, *answer(fc, height=TIP - 50, tip=TIP - 20, tip_hash="0x" + "ee" * 32))
    assert r["result"] == "fail" and r["failure_reason"] == "unknown_tip", r


def test_tip_far_above_the_monitor_fails(tmp_path):
    _, _, _, fc = make(tmp_path)
    r = evaluate(fc, *answer(fc, height=TIP - 50, tip=TIP + 11, tip_hash="0x" + "ab" * 32))
    assert r["result"] == "fail" and r["failure_reason"] == "unknown_tip", r
    r = evaluate(fc, *answer(fc, height=TIP - 50, tip=TIP + 2, tip_hash="0x" + "ab" * 32))
    assert r["result"] == "ok" and r["lag"] == 0, r


def test_recent_fork_is_not_a_miss(tmp_path):
    _, _, _, fc = make(tmp_path)
    assert csrprobe.FORK_TOLERANCE_BLOCKS >= 1
    r = evaluate(fc, *answer(fc, height=TIP - 50, tip=TIP - 1, tip_hash="0x" + "cd" * 32))
    assert r["result"] == "ok", r
    deep = TIP - csrprobe.FORK_TOLERANCE_BLOCKS - 1
    r = evaluate(fc, *answer(fc, height=TIP - 50, tip=deep, tip_hash="0x" + "cd" * 32))
    assert r["result"] == "fail" and r["failure_reason"] == "unknown_tip", r


def test_challenge_height_from_the_last_100_blocks(tmp_path):
    p, _, _, fc = make(tmp_path)
    heights = [p._new_challenge(S)["height"] for _ in range(400)]
    assert min(heights) >= TIP - 100 and max(heights) <= TIP - 1
    assert len(set(heights)) > 50, "heights are spread over the window"
    assert min(heights) < TIP - 60


# ---- D11 B, D18 A: score_v1 frozen without P ----

def test_score_v1_weights_are_frozen():
    assert scoring.SCORE_FORMULA == "score_v1"
    assert scoring.WEIGHTS == {"a30": 0.45, "a365": 0.15, "s30": 0.15, "f30": 0.15, "t": 0.10}
    assert abs(sum(scoring.WEIGHTS.values()) - 1.0) < 1e-9


def test_score_formula_is_documented_as_frozen():
    proto = open(os.path.join(ROOT, "docs", "PROTOCOL.md")).read()
    assert "score_v1" in proto and "frozen" in proto.lower()
    assert "0.45" in proto


# ---- F-MON-011: bad_binding flag ----

def test_bad_binding_sets_and_clears_the_flag(tmp_path):
    p, st, _, _ = make(tmp_path)
    pub = crypto.pubkey_from_secret(sk(9))
    rid = protocol.runner_id(pub)
    st.upsert_runner(rid, service_pubkey=to_hex(pub), peer_id="QmNine", p2p_pubkey="", reg_outpoint="",
                     mode="inbound", endpoint="http://8.8.8.8:8131", p2p_port=0, ranking_opt_in=True, now=S - 86400)
    p._record(rid, S, "inbound", "fail", "bad_binding", slot=1)
    assert "bad_binding" in st.get_runner(rid)["flags"]
    p._record(rid, S + 600, "inbound", "ok", None, slot=2, ev={"tip_number": TIP, "lag": 0, "in_sync": True})
    assert "bad_binding" not in st.get_runner(rid)["flags"]


# ---- F-MON-007: label; F-MON-012: old registry path; D8 B: 60 s documented ----

def test_peer_connected_label():
    api_src = open(os.path.join(ROOT, "csrmon", "api.py")).read()
    assert '"peer_connected"' in api_src
    assert '"p2p_verified"' not in api_src
    assert "peer_connected" in open(os.path.join(ROOT, "docs", "PROTOCOL.md")).read()


def test_old_registry_scan_is_gone():
    daemon = open(os.path.join(ROOT, "csrmon", "daemon.py")).read()
    assert "sync_registrations" not in daemon
    assert not os.path.exists(os.path.join(ROOT, "csrmon", "registry.py")) or \
        "deregistered" not in open(os.path.join(ROOT, "csrmon", "registry.py")).read()
    fields = {f for f in config_mod.Config.__dataclass_fields__}
    assert "registration_code_hash" not in fields


def test_answer_deadline_is_documented():
    proto = open(os.path.join(ROOT, "docs", "PROTOCOL.md")).read()
    assert "answer_deadline_s" in proto and "60" in proto
