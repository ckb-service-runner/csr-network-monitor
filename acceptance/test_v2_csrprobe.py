"""v2 Phase 5 acceptance: probing CSR nodes with ping protocol v1 (csrmon/csrprobe.py)."""
import random
import socket

import pytest

from csrmon import csrprobe, ping, crypto, protocol, store as store_mod, config as config_mod, geo
from csrmon.hashing import to_hex
from fakes import block_hash
from fakes_v2 import FakeChainV2, FakeCSR

I = 600
S = 1_792_281_600            # slot boundary (S % 600 == 0)
MON = (0x51).to_bytes(32, "big")
MON_PK = to_hex(crypto.pubkey_from_secret(MON))


def sk(n):
    return n.to_bytes(32, "big")


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


def rid_of(n):
    return protocol.runner_id(crypto.pubkey_from_secret(sk(n)))


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def make(tmp_path, clock, fc=None, **extra):
    base = {"probe_interval_s": I, "probe_jitter_s": 60, "probe_timeout_s": 3,
            "answer_deadline_s": 60, "allow_insecure_endpoints": "true"}
    base.update(extra)
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    lines += [f"{k} = {v}" for k, v in base.items()]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    fc = fc or FakeChainV2(tip=50_000)
    p = csrprobe.CsrProber(st, fc, c, MON, salt=b"salt", clock=clock, rng=random.Random(3))
    return p, st, c, fc


def challenge(fc, height=None, nonce=b"\x07" * 32, issued_at=S):
    return ping.make_challenge(MON, height=height or fc.tip_number - 10, issued_at=issued_at, nonce=nonce)


def csr(n, fc, clock, peer=None, **kw):
    return FakeCSR(sk(n), peer or f"QmPeer{n}", fc, MON_PK, clock=clock, **kw)


# ---------- evaluate_answer ----------

def ev(fc, ch, body, elapsed=1.0, expected_peer_id=None):
    return csrprobe.evaluate_answer(ch, body, chain=fc, network="testnet", elapsed_s=elapsed,
                                    deadline_s=60, sync_threshold=10,
                                    expected_peer_id=expected_peer_id)


def test_evaluate_ok_and_sync_states():
    fc = FakeChainV2(tip=50_000)
    ch = challenge(fc)
    out = ev(fc, ch, csr(1, fc, Clock(S)).answer(ch))
    assert out["result"] == "ok" and out["failure_reason"] is None
    assert out["peer_id"] == "QmPeer1" and out["service_pubkey"] == pk(1)
    assert out["tip_number"] == 49_999 and out["lag"] == 1 and out["in_sync"] is True
    assert out["csr_version"] == "0.1.0" and out["node_version"] == "0.210.0"
    assert out["r2_state"] == "Synced" and out["ping_mode"] == "inbound"
    out = ev(fc, ch, csr(1, fc, Clock(S), r2_state="Syncing").answer(ch))
    assert out["result"] == "ok" and out["in_sync"] is False
    out = ev(fc, ch, csr(1, fc, Clock(S), lag=9).answer(ch))       # tip 49_991 >= height 49_990
    assert out["result"] == "ok" and out["lag"] == 9 and out["in_sync"] is True


def resign(body, n=1):
    body["sig"] = ping.sign(sk(n), ping.answer_message(body["answer"]))
    return body


@pytest.mark.parametrize("case,reason", [
    ("late", "late"), ("network", "wrong_network"), ("nonce", "bad_nonce"),
    ("sig", "bad_signature"), ("binding", "bad_binding"), ("peer", "peer_id_mismatch"),
    ("block", "wrong_block_hash"), ("below", "tip_below_height"), ("format", "bad_format"),
])
def test_evaluate_failures(case, reason):
    fc = FakeChainV2(tip=50_000)
    ch = challenge(fc)
    node = csr(1, fc, Clock(S))
    body = node.answer(ch)
    elapsed, expected = 1.0, None
    if case == "late":
        elapsed = 61
    elif case == "network":
        body["answer"]["network"] = "mainnet"
        resign(body)
    elif case == "nonce":
        body = node.answer(challenge(fc, nonce=b"\x08" * 32))
    elif case == "sig":
        body["answer"]["uptime_s"] = 1
    elif case == "binding":
        body["answer"]["binding_sig"] = ping.sign(sk(1), ping.binding_message("QmOther", pk(1), "testnet"))
        resign(body)
    elif case == "peer":
        expected = "QmSomeoneElse"
    elif case == "block":
        body = csr(1, fc, Clock(S), wrong_block=True).answer(ch)
    elif case == "below":
        body["answer"]["tip_number"] = ch["height"] - 1
        resign(body)
    else:
        body["answer"].pop("uptime_s")
    out = ev(fc, ch, body, elapsed, expected)
    assert out["result"] == "fail" and out["failure_reason"] == reason


# ---------- discovery probes ----------

def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_discover_creates_inbound_runner(tmp_path):
    clock = Clock(S + 100)
    fc = FakeChainV2(tip=50_000)
    with csr(1, fc, clock) as node:
        p, st, c, _ = make(tmp_path, clock, fc, ping_port=node.port)
        p.set_peers([{"node_id": "QmPeer1", "ip": "127.0.0.1"}])
        [res] = p.discover([{"node_id": "QmPeer1", "ip": "127.0.0.1",
                             "endpoint": f"http://127.0.0.1:{node.port}"}], now=S + 100)
        assert res["result"] == "ok" and res["runner_id"] == rid_of(1)
        r = st.get_runner(rid_of(1))
        assert r["mode"] == "inbound" and r["endpoint"] == f"http://127.0.0.1:{node.port}"
        assert r["peer_id"] == "QmPeer1" and r["service_pubkey"] == pk(1) and r["status"] == "active"
        assert r["first_seen"] == S + 100 and r["ckb_version"] == "0.210.0"
        [probe] = st.probes(rid_of(1))
        assert probe["mode"] == "inbound" and probe["result"] == "ok" and probe["p2p_verified"] is True
        assert probe["slot"] == S // I
        assert st.discovery_get("127.0.0.1")["last_ok"] == S + 100
        path, raw = node.received[0]
        assert path == "/v1/challenge"


def test_discover_p2p_mismatch_and_non_csr(tmp_path):
    clock = Clock(S + 100)
    fc = FakeChainV2(tip=50_000)
    with csr(2, fc, clock) as node:
        p, st, c, _ = make(tmp_path, clock, fc)
        p.set_peers([{"node_id": "QmNotThisOne", "ip": "127.0.0.1"}])
        [res] = p.discover([{"node_id": "QmNotThisOne", "ip": "127.0.0.1",
                             "endpoint": node.url}], now=S + 100)
        assert res["result"] == "ok"
        assert st.probes(rid_of(2))[0]["p2p_verified"] is False
    [res] = p.discover([{"node_id": "QmX", "ip": "10.9.9.9",
                         "endpoint": f"http://127.0.0.1:{closed_port()}"}], now=S + 200)
    assert res["result"] == "fail" and res["failure_reason"] == "unreachable"
    got = st.discovery_get("10.9.9.9")
    assert got.pop("ip_hash") != "10.9.9.9"
    assert got == {"node_id": "QmX", "last_try": S + 200, "last_ok": None}
    p.paused = True
    assert p.discover([{"node_id": "QmY", "ip": "1.1.1.1", "endpoint": "http://1.1.1.1:1"}], now=S) == []


# ---------- scheduled inbound probes ----------

@pytest.mark.parametrize("kw,reason", [
    (dict(status=503), "node_unavailable"),
    (dict(status=429), "rate_limited"),
    (dict(status=409), "replay"),
    (dict(lag=120), "rejected_400"),
    (dict(trust="other"), "bad_monitor_key"),
    (dict(wrong_block=True), "wrong_block_hash"),
])
def test_inbound_probe_failures(tmp_path, kw, reason):
    clock = Clock(S + 400)
    fc = FakeChainV2(tip=50_000)
    trust = kw.pop("trust", None)
    node = csr(1, fc, clock, **kw)
    if trust:
        node.monitor_pubkey = pk(99)
    with node:
        p, st, c, _ = make(tmp_path, clock, fc)
        st.upsert_runner(rid_of(1), service_pubkey=pk(1), peer_id="QmPeer1", p2p_pubkey="",
                         reg_outpoint="", mode="inbound", endpoint=node.url, p2p_port=0,
                         ranking_opt_in=True, now=S - 5000)
        [rec] = p.run_due(S + 400)
    assert rec["result"] == "fail" and rec["failure_reason"] == reason


def test_inbound_schedule_and_identity(tmp_path):
    clock = Clock(S)
    fc = FakeChainV2(tip=50_000)
    with csr(1, fc, clock) as node, csr(2, fc, clock, peer="QmPeer1") as impostor:
        p, st, c, _ = make(tmp_path, clock, fc)
        st.upsert_runner(rid_of(1), service_pubkey=pk(1), peer_id="QmPeer1", p2p_pubkey="",
                         reg_outpoint="", mode="inbound", endpoint=node.url, p2p_port=0,
                         ranking_opt_in=True, now=S - 5000)
        clock.t = S + 100
        assert p.run_due(S + 100) == []                   # planned within [240, 360]
        clock.t = S + 400
        [rec] = p.run_due(S + 400)
        assert rec["result"] == "ok" and rec["mode"] == "inbound"
        assert p.run_due(S + 450) == []                   # one probe per slot
        assert len(node.received) == 1
        # the endpoint now answers with another service key
        st.upsert_runner(rid_of(1), service_pubkey=pk(1), peer_id="QmPeer1", p2p_pubkey="",
                         reg_outpoint="", mode="inbound", endpoint=impostor.url, p2p_port=0,
                         ranking_opt_in=True, now=S)
        clock.t = S + I + 400
        [rec] = p.run_due(S + I + 400)
        assert rec["result"] == "fail" and rec["failure_reason"] == "pubkey_changed"


# ---------- outbound check-ins ----------

def setup_out(tmp_path, clock, fc=None, **extra):
    p, st, c, fc = make(tmp_path, clock, fc, **extra)
    return p, st, c, fc


def do_checkin(p, node, now, ip="5.1.2.3"):
    return p.handle_checkin(node.checkin_body(), ip, now)


def answer_for(node, ch, mode="outbound"):
    body = node.answer(ch, ping_mode=mode)
    return body


def test_outbound_flow(tmp_path):
    clock = Clock(S + 30)
    p, st, c, fc = setup_out(tmp_path, clock)
    node = csr(3, fc, clock)
    p.set_peers([{"node_id": "QmPeer3", "ip": "9.9.9.9"}])
    status, body = do_checkin(p, node, S + 30)
    assert status == 200 and set(body) == {"challenge"}
    ch = body["challenge"]
    assert list(ch) == ["nonce", "height", "issued_at", "monitor_sig"]
    assert ping.verify_challenge(ch, MON_PK)
    assert 50_000 - 100 <= ch["height"] <= 50_000 - 1 and ch["issued_at"] == S + 30
    assert do_checkin(p, node, S + 31) == (429, {"error": "challenge_open"})
    status, res = p.handle_answer(answer_for(node, ch), "5.1.2.3", S + 32)
    assert (status, res) == (200, {"result": "ok"})
    r = st.get_runner(rid_of(3))
    assert r["mode"] == "outbound" and r["endpoint"] == "" and r["peer_id"] == "QmPeer3"
    assert r["first_seen"] == S + 32
    [probe] = st.probes(rid_of(3))
    assert probe["mode"] == "outbound" and probe["slot"] == S // I and probe["p2p_verified"] is True
    assert probe["ip_hash"] == geo.ip_hash("5.1.2.3", b"salt")
    assert do_checkin(p, node, S + 100) == (429, {"error": "slot_done"})


def test_outbound_errors(tmp_path):
    clock = Clock(S + 30)
    p, st, c, fc = setup_out(tmp_path, clock)
    node = csr(4, fc, clock)
    good = node.checkin_body()
    assert p.handle_checkin({"peer_id": 1}, "1.1.1.1", S + 30) == (400, {"error": "bad_request"})
    assert p.handle_checkin(dict(good, network="mainnet"), "1.1.1.1", S + 30) == \
        (400, {"error": "wrong_network"})
    assert p.handle_checkin(dict(good, peer_id="QmOther"), "1.1.1.1", S + 30) == \
        (401, {"error": "bad_signature"})
    p.paused = True
    assert p.handle_checkin(good, "1.1.1.1", S + 30) == (503, {"error": "monitor_paused"})
    p.paused = False
    assert p.handle_answer({"nope": 1}, "1.1.1.1", S + 30) == (400, {"error": "bad_request"})
    other = node.answer(challenge(fc, nonce=b"\x09" * 32))
    assert p.handle_answer(other, "1.1.1.1", S + 30) == (409, {"error": "unknown_nonce"})
    status, body = p.handle_checkin(good, "1.1.1.1", S + 30)
    late = answer_for(node, body["challenge"])
    assert p.handle_answer(late, "1.1.1.1", S + 30 + 61) == \
        (422, {"result": "fail", "failure_reason": "late"})
    assert st.get_runner(rid_of(4)) is None              # failures do not create runners
    clock.t = S + I + 30
    status, body = p.handle_checkin(good, "1.1.1.1", S + I + 30)
    broken = answer_for(node, body["challenge"])
    broken["answer"].pop("r2_state")
    assert p.handle_answer(broken, "1.1.1.1", S + I + 31) == \
        (422, {"result": "fail", "failure_reason": "bad_format"})


def test_unanswered_challenge_and_known_runner(tmp_path):
    clock = Clock(S + 30)
    p, st, c, fc = setup_out(tmp_path, clock)
    node = csr(5, fc, clock)
    status, body = do_checkin(p, node, S + 30)
    p.handle_answer(answer_for(node, body["challenge"]), "1.1.1.1", S + 31)   # runner exists now
    clock.t = S + I + 20
    cb = node.checkin_body()                                   # v1.1: only a signed check-in can miss
    cb["ts"] = S + I + 20
    cb["checkin_sig"] = ping.sign(sk(5), ping.checkin_message(
        cb["peer_id"], cb["service_pubkey"], cb["network"], cb["ts"]))
    status, body = p.handle_checkin(cb, "5.1.2.3", S + I + 20)
    assert status == 200
    recs = p.run_due(S + I + 81)                                # 61 s later, no answer
    assert [(r["runner_id"], r["result"], r["failure_reason"]) for r in recs] == \
        [(rid_of(5), "fail", "no_answer")]
    assert st.probes(rid_of(5))[-1]["slot"] == S // I + 1


def test_outbound_slot_grace_and_misses(tmp_path):
    clock = Clock(S)
    p, st, c, fc = setup_out(tmp_path, clock)                 # monitor starts at S
    node = csr(6, fc, clock)
    s0 = S // I

    def visit(t):
        clock.t = t
        status, body = do_checkin(p, node, t)
        assert status == 200, body
        assert p.handle_answer(answer_for(node, body["challenge"]), "1.1.1.1", t + 1)[0] == 200

    visit(S + 590)                    # slot s0
    visit(S + 1195)                   # slot s0+1
    visit(S + 1800 + 100)             # slot s0+3: fills the empty slot s0+2 (within grace)
    assert sorted(p["slot"] for p in st.probes(rid_of(6))) == [s0, s0 + 1, s0 + 2]
    assert p.run_due(S + 1800 + 200) == []                    # s0+2 filled, s0+3 still open
    visit(S + 2400 + 50)              # slot s0+4: fills s0+3
    recs = p.run_due(S + 4 * I + 301)
    assert recs == []                                          # s0+4 not closed yet (grace)
    recs = p.run_due(S + 5 * I + 301)                          # s0+4 closed without a probe
    assert [(r["slot"], r["failure_reason"]) for r in recs] == [(s0 + 4, "no_checkin")]
    assert p.run_due(S + 5 * I + 302) == []
    p.paused = True
    p.run_due(S + 5 * I + 303)                                 # slot s0+5 seen while paused
    p.paused = False
    recs = p.run_due(S + 6 * I + 301)
    assert [(r["slot"], r["result"], r["failure_reason"]) for r in recs] == \
        [(s0 + 5, "excluded", "monitor_paused")]
