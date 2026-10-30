"""Phase 6 acceptance: P2P full-node check (MON-FN-2, MON-FN-3), since node-identity-monitor through
the monitor's own node."""
import random

import pytest

from csrmon import p2p, protocol, crypto, store as store_mod, config as config_mod
from fakes import block_hash
from fakes_v2 import FakeChainV2, peer_entry


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
    return {"tmp": tmp_path, "cfg": cfg, "st": st, "rid": rid, "peer": peer}


def synced_peer(node_id, number):
    e = peer_entry(node_id, ["/ip4/1.2.3.4/tcp/8115"])
    e["sync_state"] = {"best_known_header_number": hex(number), "best_known_header_hash": block_hash(number)}
    return e


def test_scheduler(env):
    fc = FakeChainV2(tip=200_000)
    fc.peers = [synced_peer(env["peer"], 200_000)]
    sched = p2p.P2PScheduler(env["st"], fc, env["cfg"], rng=random.Random(5))
    assert sched.run_due(0) == []                       # planned later in the period
    first = sched.run_due(950)                          # planned times are in [50, 900)
    assert first == [{"runner_id": env["rid"], "result": "ok", "reason": None}]
    assert sched.run_due(990) == []                     # once per period
    fc.peers = []
    assert sched.run_due(1950) == [{"runner_id": env["rid"], "result": "fail", "reason": "not_connected"}]
    rows = env["st"].p2p_checks(env["rid"])
    assert [r["result"] for r in rows] == ["ok", "fail"] and rows[1]["reason"] == "not_connected"
    paused = p2p.P2PScheduler(env["st"], fc, env["cfg"], rng=random.Random(5), paused=lambda: True)
    assert paused.run_due(2950) == []                   # nothing while probing is paused
    env["st"].set_status(env["rid"], "deregistered")
    assert sched.run_due(2950) == []


def test_removed_helper_keys_are_rejected(tmp_path):
    for line in ('p2p_check_cmd = "/bin/true"', "p2p_check_timeout_s = 120"):
        (tmp_path / "c.toml").write_text('network = "testnet"\npublic_url = "https://m.example"\n'
                                         f'db_path = "{tmp_path}/t.db"\nkey_path = "{tmp_path}/k"\n{line}\n')
        with pytest.raises(config_mod.ConfigError, match="no longer supported"):
            config_mod.load_config(str(tmp_path / "c.toml"))
