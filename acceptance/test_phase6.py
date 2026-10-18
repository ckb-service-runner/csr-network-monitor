"""Phase 6 acceptance: external P2P full-node check (MON-FN-2, MON-FN-3)."""
import json
import random
import sys
import textwrap

import pytest

from csrmon import p2p, protocol, crypto, store as store_mod, config as config_mod
from fakes import FakeChain

HELPER = textwrap.dedent('''
    import hashlib, json, sys, time
    mode, log = sys.argv[1], sys.argv[2]
    req = json.loads(sys.stdin.read())
    open(log, "w").write(json.dumps(req))
    def bh(n):
        d = hashlib.blake2b(b"block" + n.to_bytes(8, "little"), digest_size=32,
                            person=b"ckb-default-hash").digest()
        return "0x" + d.hex()
    if mode == "fail":
        sys.exit(1)
    if mode == "slow":
        time.sleep(5)
    if mode == "garbage":
        print("hello")
        sys.exit(0)
    heights = req["heights"]
    if mode == "missing":
        heights = heights[:-1]
    served = [{"height": h, "hash": bh(h)} for h in heights]
    if mode == "wronghash":
        served[0]["hash"] = "0x" + "00" * 32
    seen = req["peer_id"] if mode != "wrongpeer" else "QmSomebodyElse"
    print(json.dumps({"peer_id_seen": seen, "served": served, "latency_ms": 321}))
''')


def sk(n):
    return n.to_bytes(32, "big")


def test_choose_heights():
    rng = random.Random(1)
    for _ in range(20):
        hs = p2p.choose_heights(100_000, rng)
        assert hs == sorted(hs) and len(set(hs)) == 4 and len(hs) == 4
        assert sum(1 for h in hs if h >= 100_000 - 999) == 2
        assert sum(1 for h in hs if h <= 100_000 - 1000) == 2
        assert all(1 <= h <= 100_000 for h in hs)
    small = p2p.choose_heights(50, rng)
    assert small == sorted(set(small)) and 1 <= len(small) <= 4
    assert all(1 <= h <= 50 for h in small)


def test_address_for():
    base = {"mode": "pull", "p2p_port": 8115}
    assert p2p.address_for(dict(base, endpoint="https://1.2.3.4:8443")) == "/ip4/1.2.3.4/tcp/8115"
    assert p2p.address_for(dict(base, endpoint="https://[2001:db8::1]/")) == "/ip6/2001:db8::1/tcp/8115"
    assert p2p.address_for(dict(base, endpoint="https://node.example.org")) == \
        "/dns4/node.example.org/tcp/8115"
    assert p2p.address_for(dict(base, endpoint="https://x.example", p2p_port=0)) is None
    assert p2p.address_for({"mode": "push", "p2p_port": 8115, "endpoint": ""}) is None


@pytest.fixture
def env(tmp_path):
    script = tmp_path / "helper.py"
    script.write_text(HELPER)
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"',
             "p2p_interval_s = 1000"]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    cfg = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(cfg.db_path)
    pk = crypto.pubkey_from_secret(sk(1))
    rid = protocol.runner_id(pk)
    peer = protocol.peer_id_from_pubkey(crypto.pubkey_from_secret(sk(101)))
    st.upsert_runner(rid, service_pubkey="0x" + pk.hex(), peer_id=peer, p2p_pubkey="0x02",
                     reg_outpoint="0x00:0", mode="pull", endpoint="https://1.2.3.4",
                     p2p_port=8115, ranking_opt_in=True, now=0)
    return {"tmp": tmp_path, "script": script, "cfg": cfg, "st": st, "rid": rid, "peer": peer}


def checker(env, mode, timeout=10):
    log = env["tmp"] / "req.json"
    cmd = f"{sys.executable} {env['script']} {mode} {log}"
    return p2p.P2PChecker(cmd, timeout_s=timeout, network="testnet"), log


def run(env, mode, timeout=10):
    ck, log = checker(env, mode, timeout)
    fc = FakeChain(tip=200_000)
    runner = env["st"].get_runner(env["rid"])
    res = p2p.run_p2p_check(env["st"], fc, ck, runner, now=1000, rng=random.Random(3))
    return res, log


def test_check_ok_and_request(env):
    res, log = run(env, "ok")
    assert res["result"] == "ok" and res["served"] == 4 and res["peer_id_seen"] == env["peer"]
    req = json.loads(log.read_text())
    assert req["v"] == 1 and req["network"] == "testnet" and req["peer_id"] == env["peer"]
    assert req["address"] == "/ip4/1.2.3.4/tcp/8115" and req["timeout_s"] == 10
    assert req["heights"] == res["heights"] and len(req["heights"]) == 4
    [row] = env["st"].p2p_checks(env["rid"])
    assert row["result"] == "ok" and row["served"] == 4 and row["latency_ms"] == 321
    assert row["peer_id_seen"] == env["peer"] and row["ts"] == 1000


@pytest.mark.parametrize("mode,result", [
    ("missing", "fail"), ("wronghash", "fail"), ("fail", "error"),
    ("garbage", "error"), ("slow", "error"),
])
def test_check_failures(env, mode, result):
    res, _ = run(env, mode, timeout=2)
    assert res["result"] == result
    assert env["st"].p2p_checks(env["rid"])[0]["result"] == result
    assert env["st"].get_runner(env["rid"])["flags"] == []


def test_identity_mismatch_flag_set_and_cleared(env):
    res, _ = run(env, "wrongpeer")
    assert res["result"] == "identity_mismatch" and res["peer_id_seen"] == "QmSomebodyElse"
    assert env["st"].get_runner(env["rid"])["flags"] == ["identity_mismatch"]
    run(env, "fail")
    assert env["st"].get_runner(env["rid"])["flags"] == ["identity_mismatch"]
    run(env, "ok")
    assert env["st"].get_runner(env["rid"])["flags"] == []


def test_scheduler(env):
    ck, _ = checker(env, "ok")
    fc = FakeChain(tip=200_000)
    sched = p2p.P2PScheduler(env["st"], fc, ck, env["cfg"], rng=random.Random(5))
    assert sched.run_due(0) == []                       # planned later in the period
    first = sched.run_due(950)                          # planned times are in [50, 900)
    assert [r["result"] for r in first] == ["ok"]
    assert sched.run_due(990) == []                     # once per period
    assert len(sched.run_due(1950)) == 1                # next period
    assert len(env["st"].p2p_checks(env["rid"])) == 2
    env["st"].set_status(env["rid"], "deregistered")
    assert sched.run_due(2950) == []
    none = p2p.P2PScheduler(env["st"], fc, None, env["cfg"], rng=random.Random(5))
    assert none.run_due(5000) == []
