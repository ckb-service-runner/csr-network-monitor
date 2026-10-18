"""Phase 5 acceptance: challenge verification, pull probes, push check-ins, slots."""
import random
import socket
import time

import pytest

from csrmon import prober as prober_mod, protocol, crypto, store as store_mod, config as config_mod, geo
from csrmon.hashing import from_hex
from fakes import FakeChain, FakeRunner, block_hash

I = 600                       # probe interval used in these tests
S = 1_760_000_400             # a slot boundary: S % 600 == 0
MON = (11).to_bytes(32, "big")


def sk(n):
    return n.to_bytes(32, "big")


def peer(n):
    return protocol.peer_id_from_pubkey(crypto.pubkey_from_secret(sk(n)))


# ---------- evaluate_response ----------

def ch_for(fc, height=None, nonce=b"\x05" * 32):
    return protocol.make_challenge(MON, network="testnet", monitor_tip=fc.tip_number,
                                   block_height=height or fc.tip_number - 20,
                                   issued_at=S, nonce=nonce)


def resp(fc, ch, secret=sk(1), p2p=101, tip=None, **over):
    tip = fc.tip_number - 1 if tip is None else tip
    fields = dict(peer_id=peer(p2p), tip_number=tip, tip_hash=block_hash(tip),
                  block_hash=block_hash(ch["block_height"]), ibd=False, peers_out=8,
                  csr_version="0.1.0", ckb_version="0.203.0")
    fields.update(over)
    return protocol.sign_response(secret, ch, **fields)


def ev(fc, ch, r, elapsed=0.2):
    return prober_mod.evaluate_response(
        ch, r, service_pubkey=crypto.pubkey_from_secret(sk(1)), peer_id=peer(101),
        chain=fc, elapsed_s=elapsed, timeout_s=5, sync_threshold=10)


def test_evaluate_ok():
    fc = FakeChain(tip=10_000)
    ch = ch_for(fc)
    out = ev(fc, ch, resp(fc, ch))
    assert out["result"] == "ok" and out["failure_reason"] is None
    assert out["tip_number"] == 9_999 and out["lag"] == 1 and out["in_sync"] is True
    assert out["peers_out"] == 8 and out["csr_version"] == "0.1.0" and out["ckb_version"] == "0.203.0"


def test_evaluate_not_synced_is_answered_but_out_of_sync():
    fc = FakeChain(tip=10_000)
    ch = ch_for(fc)
    out = ev(fc, ch, resp(fc, ch, tip=9_985))
    assert out["result"] == "ok" and out["lag"] == 15 and out["in_sync"] is False
    out = ev(fc, ch, resp(fc, ch, tip=9_990))
    assert out["lag"] == 10 and out["in_sync"] is True
    out = ev(fc, ch, resp(fc, ch, ibd=True))
    assert out["result"] == "ok" and out["in_sync"] is False


def test_evaluate_runner_slightly_ahead():
    fc = FakeChain(tip=10_000)
    ch = ch_for(fc)
    out = ev(fc, ch, resp(fc, ch, tip=10_003, tip_hash="0x" + "cd" * 32))
    assert out["result"] == "ok" and out["lag"] == 0 and out["in_sync"] is True
    out = ev(fc, ch, resp(fc, ch, tip=10_011, tip_hash="0x" + "cd" * 32))
    assert out == {**out, "result": "fail", "failure_reason": "unknown_tip"}


@pytest.mark.parametrize("case,reason", [
    ("late", "late"),
    ("nonce", "bad_nonce"),
    ("sig", "bad_signature"),
    ("peer", "peer_id_mismatch"),
    ("block", "wrong_block_hash"),
    ("tiphash", "unknown_tip"),
])
def test_evaluate_failures(case, reason):
    fc = FakeChain(tip=10_000)
    ch = ch_for(fc)
    elapsed = 0.2
    if case == "late":
        r, elapsed = resp(fc, ch), 5.5
    elif case == "nonce":
        r = resp(fc, ch_for(fc, nonce=b"\x06" * 32))
    elif case == "sig":
        r = resp(fc, ch, secret=sk(2))
    elif case == "peer":
        r = resp(fc, ch, p2p=102)
    elif case == "block":
        r = resp(fc, ch, block_hash="0x" + "00" * 32)
    else:
        fc.forked[9_999] = "0x" + "ee" * 32   # runner's tip hash is not on our main chain
        r = resp(fc, ch)
    out = ev(fc, ch, r, elapsed)
    assert out["result"] == "fail" and out["failure_reason"] == reason


@pytest.mark.parametrize("mutate", [
    lambda r: r.pop("tip_hash"),
    lambda r: r.update(tip_number="9999"),
    lambda r: r.update(tip_number=True),
    lambda r: r.update(peers_out=-1),
    lambda r: r.update(ibd="no"),
    lambda r: r.update(v=2),
])
def test_evaluate_bad_format(mutate):
    fc = FakeChain(tip=10_000)
    ch = ch_for(fc)
    r = resp(fc, ch)
    mutate(r)
    out = ev(fc, ch, r)
    assert out["result"] == "fail" and out["failure_reason"] == "bad_format"
    assert ev(fc, ch, "not a dict")["failure_reason"] == "bad_format"


def test_slot_of():
    assert prober_mod.slot_of(S, I) == S // I
    assert prober_mod.slot_of(S + 599.9, I) == S // I
    assert prober_mod.slot_of(S + 600, I) == S // I + 1


# ---------- prober fixtures ----------

class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def make_cfg(tmp_path, **extra):
    base = {"probe_interval_s": I, "probe_jitter_s": 60, "probe_timeout_s": 2,
            "allow_insecure_endpoints": "true"}
    base.update(extra)
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    lines += [f"{k} = {v}" for k, v in base.items()]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    return config_mod.load_config(str(tmp_path / "c.toml"))


def add(st, n, mode="pull", endpoint="", first_seen=S - 10 * I, status=None):
    pk = crypto.pubkey_from_secret(sk(n))
    rid = protocol.runner_id(pk)
    st.upsert_runner(rid, service_pubkey="0x" + pk.hex(), peer_id=peer(100 + n),
                     p2p_pubkey="0x" + crypto.pubkey_from_secret(sk(100 + n)).hex(),
                     reg_outpoint="0x" + "aa" * 32 + ":0", mode=mode, endpoint=endpoint,
                     p2p_port=0, ranking_opt_in=True, now=first_seen)
    if status:
        st.set_status(rid, status)
    return rid


def make_prober(tmp_path, fc, clock, geodb=None, **cfg):
    c = make_cfg(tmp_path, **cfg)
    st = store_mod.Store(c.db_path)
    p = prober_mod.Prober(st, fc, c, MON, geo=geodb, salt=b"salt", clock=clock,
                          rng=random.Random(7))
    return p, st, c


def closed_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# ---------- pull probes ----------

def test_planned_time_jitter(tmp_path):
    p, st, c = make_prober(tmp_path, FakeChain(), Clock(S))
    slot = S // I
    times = [p.planned_time("0xabc", slot + k) - (slot + k) * I for k in range(50)]
    assert all(240 <= t <= 360 for t in times)
    assert len(set(times)) > 10
    assert p.planned_time("0xabc", slot) == p.planned_time("0xabc", slot)


def test_pull_probe_ok_and_schedule(tmp_path):
    fc = FakeChain(tip=50_000)
    clock = Clock(S)
    p, st, c = make_prober(tmp_path, fc, clock)
    with FakeRunner(sk(1), sk(101), fc) as fr:
        rid = add(st, 1, endpoint=fr.url)
        assert p.run_due(S + 100) == []          # before the earliest planned time
        assert fr.received == []
        recs = p.run_due(S + 400)
        assert len(recs) == 1 and recs[0]["runner_id"] == rid and recs[0]["result"] == "ok"
        assert p.run_due(S + 500) == []          # one probe per slot
        assert len(fr.received) == 1
        path, challenge = fr.received[0]
        assert path == "/csr/v1/probe"
        assert protocol.verify_challenge(challenge, crypto.pubkey_from_secret(MON))
        assert 50_000 - 99 <= challenge["block_height"] <= 50_000
        [row] = st.probes(rid)
        assert row["mode"] == "pull" and row["slot"] == S // I and row["result"] == "ok"
        assert row["lag"] == 1 and row["in_sync"] is True and row["latency_ms"] >= 0
        assert row["tip_number"] == 49_999
        assert st.get_runner(rid)["last_seen"] == row["ts"]


@pytest.mark.parametrize("kind,reason", [
    ("wrong_block", "wrong_block_hash"),
    ("status", "bad_status"),
    ("garbage", "bad_format"),
    ("slow", "timeout"),
])
def test_pull_probe_failures(tmp_path, kind, reason):
    fc = FakeChain(tip=50_000)
    p, st, c = make_prober(tmp_path, fc, Clock(S), probe_timeout_s=1)
    kw = {"wrong_block": dict(wrong_block=True), "status": dict(status=500),
          "garbage": dict(garbage=True), "slow": dict(delay=1.6)}[kind]
    with FakeRunner(sk(1), sk(101), fc, **kw) as fr:
        rid = add(st, 1, endpoint=fr.url)
        [rec] = p.run_due(S + 400)
    assert rec["result"] == "fail" and rec["failure_reason"] == reason
    assert st.probes(rid)[0]["failure_reason"] == reason


def test_pull_probe_unreachable(tmp_path):
    p, st, c = make_prober(tmp_path, FakeChain(), Clock(S))
    rid = add(st, 1, endpoint=f"http://127.0.0.1:{closed_port()}")
    [rec] = p.run_due(S + 400)
    assert rec["failure_reason"] == "unreachable"


def test_pull_probes_run_concurrently(tmp_path):
    fc = FakeChain(tip=50_000)
    p, st, c = make_prober(tmp_path, fc, Clock(S), probe_timeout_s=3)
    runners = [FakeRunner(sk(n), sk(100 + n), fc, delay=0.5) for n in range(1, 13)]
    for fr in runners:
        fr.__enter__()
    try:
        for n, fr in enumerate(runners, start=1):
            add(st, n, endpoint=fr.url)
        t0 = time.monotonic()
        recs = p.run_due(S + 599)
        took = time.monotonic() - t0
    finally:
        for fr in runners:
            fr.__exit__()
    assert len(recs) == 12 and all(r["result"] == "ok" for r in recs)
    assert took < 3.0


def test_paused_and_inactive_runners(tmp_path):
    fc = FakeChain()
    p, st, c = make_prober(tmp_path, fc, Clock(S))
    with FakeRunner(sk(1), sk(101), fc) as fr:
        rid = add(st, 1, endpoint=fr.url)
        add(st, 2, endpoint=fr.url, status="opted_out")
        add(st, 3, endpoint=fr.url, status="deregistered")
        p.paused = True
        [rec] = p.run_due(S + 599)
        assert rec["runner_id"] == rid
        assert rec["result"] == "excluded" and rec["failure_reason"] == "monitor_paused"
        assert fr.received == []


# ---------- push check-ins ----------

GEO_IP = "5.1.2.3"


def geodb(tmp_path):
    (tmp_path / "c.csv").write_text("5.1.0.0,5.1.255.255,DE\n")
    (tmp_path / "a.csv").write_text("5.1.0.0,5.1.255.255,3320,Telekom\n")
    return geo.GeoDB(str(tmp_path / "c.csv"), str(tmp_path / "a.csv"))


def answer(fc, challenge, secret=sk(1), p2p=101):
    tip = fc.tip_number - 2
    return protocol.sign_response(
        secret, challenge, peer_id=peer(p2p), tip_number=tip, tip_hash=block_hash(tip),
        block_hash=block_hash(challenge["block_height"]), ibd=False, peers_out=6,
        csr_version="0.1.0", ckb_version="0.203.0")


def test_push_flow(tmp_path):
    fc = FakeChain(tip=70_000)
    p, st, c = make_prober(tmp_path, fc, Clock(S), geodb=geodb(tmp_path))
    rid = add(st, 1, mode="push")
    now = S + 30
    status, body = p.handle_checkin(protocol.make_checkin(sk(1), "testnet", now), GEO_IP, now)
    assert status == 200 and body["deadline_s"] == 2
    ch = body["challenge"]
    assert protocol.verify_challenge(ch, crypto.pubkey_from_secret(MON))
    assert ch["network"] == "testnet" and ch["monitor_tip"] == 70_000
    status, body2 = p.handle_checkin(protocol.make_checkin(sk(1), "testnet", now + 1), GEO_IP, now + 1)
    assert (status, body2) == (429, {"error": "challenge_open"})
    status, res = p.handle_checkin_response({"runner_id": rid, "response": answer(fc, ch)}, GEO_IP, now + 1)
    assert status == 200 and res["result"] == "ok" and res["failure_reason"] is None
    assert res["lag"] == 2 and res["in_sync"] is True
    status, body3 = p.handle_checkin(protocol.make_checkin(sk(1), "testnet", now + 60), GEO_IP, now + 60)
    assert (status, body3) == (429, {"error": "slot_done"})
    [row] = st.probes(rid)
    assert row["mode"] == "push" and row["slot"] == S // I and row["result"] == "ok"
    assert row["country"] == "DE" and row["asn"] == 3320
    assert row["ip_hash"] == geo.ip_hash(GEO_IP, b"salt")
    r = st.get_runner(rid)
    assert r["country"] == "DE" and r["region"] == "EU" and r["asn"] == 3320


def test_push_errors(tmp_path):
    fc = FakeChain(tip=70_000)
    p, st, c = make_prober(tmp_path, fc, Clock(S))
    rid = add(st, 1, mode="push")
    now = S + 30
    good = protocol.make_checkin(sk(1), "testnet", now)
    assert p.handle_checkin({"v": 1}, "1.1.1.1", now) == (400, {"error": "bad_request"})
    assert p.handle_checkin("x", "1.1.1.1", now) == (400, {"error": "bad_request"})
    unknown = protocol.make_checkin(sk(9), "testnet", now)
    assert p.handle_checkin(unknown, "1.1.1.1", now) == (404, {"error": "unknown_runner"})
    assert p.handle_checkin(protocol.make_checkin(sk(1), "testnet", now - 121), "1.1.1.1", now) == \
        (400, {"error": "stale_timestamp"})
    forged = dict(good, sig=protocol.make_checkin(sk(2), "testnet", now)["sig"])
    assert p.handle_checkin(forged, "1.1.1.1", now) == (401, {"error": "bad_signature"})
    assert p.handle_checkin(protocol.make_checkin(sk(1), "mainnet", now), "1.1.1.1", now) == \
        (401, {"error": "bad_signature"})
    assert p.handle_checkin_response({"runner_id": rid, "response": {}}, "1.1.1.1", now) == \
        (409, {"error": "no_open_challenge"})
    assert p.handle_checkin_response({"nope": 1}, "1.1.1.1", now) == (400, {"error": "bad_request"})
    p.paused = True
    assert p.handle_checkin(good, "1.1.1.1", now) == (503, {"error": "monitor_paused"})
    p.paused = False
    status, body = p.handle_checkin(good, "1.1.1.1", now)
    assert status == 200
    status, res = p.handle_checkin_response(
        {"runner_id": rid, "response": answer(fc, body["challenge"])}, "1.1.1.1", now + 2.5)
    assert status == 200 and res["result"] == "fail" and res["failure_reason"] == "late"


def test_unanswered_challenge_is_a_miss(tmp_path):
    fc = FakeChain()
    p, st, c = make_prober(tmp_path, fc, Clock(S))
    rid = add(st, 1, mode="push")
    status, _ = p.handle_checkin(protocol.make_checkin(sk(1), "testnet", S + 30), "1.1.1.1", S + 30)
    assert status == 200
    recs = p.run_due(S + 40)
    assert [(r["runner_id"], r["result"], r["failure_reason"]) for r in recs] == \
        [(rid, "fail", "no_response")]
    assert st.probes(rid)[0]["slot"] == S // I
    # the challenge is gone; a late answer is refused
    assert p.handle_checkin_response({"runner_id": rid, "response": {}}, "1.1.1.1", S + 41)[0] == 409


def test_missed_push_slots(tmp_path):
    fc = FakeChain()
    clock = Clock(S + 10)          # monitor starts 10 s into a slot
    p, st, c = make_prober(tmp_path, fc, clock)
    old = add(st, 1, mode="push")                       # registered long ago
    new = add(st, 2, mode="push", first_seen=S + I + 5)  # registered during slot S/I+1
    recs = p.run_due(S + 3 * I + 1)
    got = sorted((r["runner_id"], r["slot"], r["failure_reason"]) for r in recs)
    s0 = S // I
    # slot s0 is partly before the start: not counted. slot s0+3 is still open.
    assert got == sorted([(old, s0 + 1, "no_checkin"), (old, s0 + 2, "no_checkin"),
                          (new, s0 + 2, "no_checkin")])
    assert p.run_due(S + 3 * I + 2) == []
    p.paused = True
    p.run_due(S + 3 * I + 3)
    p.paused = False
    recs = p.run_due(S + 4 * I + 1)
    assert sorted((r["slot"], r["result"], r["failure_reason"]) for r in recs) == \
        [(s0 + 3, "excluded", "monitor_paused")] * 2
