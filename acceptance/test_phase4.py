"""Phase 4 acceptance: node RPC client, registration discovery, tip cross-check."""
import socket

import pytest

from csrmon import chain as chain_mod, registry, store as store_mod, config as config_mod, protocol, crypto
from fakes import (FakeChain, FakeRpcServer, make_registration_cell, block_hash, block_ts,
                   REG_CODE_HASH, cell, GENESIS_MS)


def sk(n):
    return n.to_bytes(32, "big")


def test_rpc_chain_basic():
    fc = FakeChain(tip=5000)
    with FakeRpcServer(fc) as srv:
        rc = chain_mod.RpcChain(srv.url)
        assert rc.tip() == (5000, block_hash(5000))
        assert rc.block_hash(42) == block_hash(42)
        assert rc.block_hash(6000) is None
        assert rc.header(7) == {"number": 7, "hash": block_hash(7), "timestamp_ms": block_ts(7)}
        assert rc.header(6000) is None
        assert rc.call("get_block_hash", ["0x5"]) == block_hash(5)


def test_block_at_time():
    fc = FakeChain(tip=5000)
    with FakeRpcServer(fc) as srv:
        rc = chain_mod.RpcChain(srv.url)
        assert rc.block_at_time(block_ts(1234)) == 1234
        assert rc.block_at_time(block_ts(1234) + 7999) == 1234
        assert rc.block_at_time(block_ts(1234) - 1) == 1233
        assert rc.block_at_time(GENESIS_MS - 10) == 0
        assert rc.block_at_time(block_ts(99999)) == 5000
        srv.calls.clear()
        assert rc.block_at_time(block_ts(777)) == 777
        assert srv.calls.count("get_header_by_number") <= 30  # binary search, not a scan


def test_rpc_errors():
    with FakeRpcServer() as srv:
        rc = chain_mod.RpcChain(srv.url)
        with pytest.raises(chain_mod.RpcError):
            rc.call("fail_please", [])
        with pytest.raises(chain_mod.RpcError):
            rc.call("no_such_method", [])
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    with pytest.raises(chain_mod.RpcError):
        chain_mod.RpcChain(f"http://127.0.0.1:{port}", timeout=2).tip()


def test_get_cells_pages_and_send():
    fc = FakeChain()
    script = {"code_hash": REG_CODE_HASH, "hash_type": "type", "args": "0x"}
    for i in range(250):
        fc.cells.append(cell(dict(script, args="0x" + f"{i:04x}"), "0x", "0x" + f"{i:064x}"))
    with FakeRpcServer(fc, page_limit=100) as srv:
        rc = chain_mod.RpcChain(srv.url)
        got = list(rc.get_cells(script, "type"))
        assert len(got) == 250
        assert got[0]["out_point"]["tx_hash"] == "0x" + f"{0:064x}"
        exact = list(rc.get_cells(dict(script, args="0x0007"), "type", exact=True))
        assert len(exact) == 1
        assert srv.calls.count("get_cells") >= 3
        h = rc.send_transaction({"version": "0x0"})
        assert h.startswith("0x") and fc.sent == [{"version": "0x0"}]


# ---------- registration discovery ----------

def make_config(tmp_path, **extra):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"',
             f'registration_code_hash = "{REG_CODE_HASH}"']
    for k, v in extra.items():
        lines.append(f"{k} = {v}")
    p = tmp_path / "c.toml"
    p.write_text("\n".join(lines) + "\n")
    return config_mod.load_config(str(p))


def test_sync_registrations(tmp_path):
    fc = FakeChain()
    c_pull, reg_pull = make_registration_cell(sk(1), sk(101), tx_byte=1)
    c_push, reg_push = make_registration_cell(sk(2), sk(102), mode="push", endpoint="",
                                              p2p_port=0, tx_byte=2)
    c_dup, _ = make_registration_cell(sk(1), sk(101), endpoint="https://dup.example", tx_byte=3, block=9)
    c_main, _ = make_registration_cell(sk(4), sk(104), network="mainnet", tx_byte=4)
    c_http, _ = make_registration_cell(sk(5), sk(105), endpoint="http://insecure.example", tx_byte=5)
    c_bad = cell({"code_hash": REG_CODE_HASH, "hash_type": "type", "args": "0x"}, "0x0102", "0x" + "06" * 32)
    c_opt, reg_opt = make_registration_cell(sk(7), sk(107), ranking_opt_in=False, tx_byte=7)
    fc.cells = [c_pull, c_push, c_dup, c_main, c_http, c_bad, c_opt]
    cfg = make_config(tmp_path)
    st = store_mod.Store(cfg.db_path)
    res = registry.sync_registrations(st, fc, cfg, now=1000)
    assert sorted(res["added"]) == sorted([reg_pull.runner_id, reg_push.runner_id, reg_opt.runner_id])
    assert res["updated"] == [] and res["removed"] == []
    assert res["invalid"] == 4  # duplicate, mainnet, insecure http, garbage
    r = st.get_runner(reg_pull.runner_id)
    assert r["endpoint"] == "https://runner.example.org"   # first cell wins over duplicate
    assert r["peer_id"] == reg_pull.peer_id
    assert r["service_pubkey"] == "0x" + reg_pull.service_pubkey.hex()
    assert r["p2p_pubkey"] == "0x" + reg_pull.p2p_pubkey.hex()
    assert r["reg_outpoint"] == "0x" + "01" * 32 + ":0"
    assert r["mode"] == "pull" and r["p2p_port"] == 8115 and r["first_seen"] == 1000
    assert st.get_runner(reg_push.runner_id)["mode"] == "push"
    assert st.get_runner(reg_opt.runner_id)["status"] == "opted_out"

    # second sync: nothing changed
    res = registry.sync_registrations(st, fc, cfg, now=2000)
    assert res["added"] == [] and res["updated"] == [] and res["removed"] == []

    # endpoint change, push cell destroyed
    c_pull2, _ = make_registration_cell(sk(1), sk(101), endpoint="https://moved.example", tx_byte=8)
    fc.cells = [c_pull2, c_opt]
    res = registry.sync_registrations(st, fc, cfg, now=3000)
    assert res["updated"] == [reg_pull.runner_id]
    assert res["removed"] == [reg_push.runner_id]
    assert st.get_runner(reg_push.runner_id)["status"] == "deregistered"
    assert st.get_runner(reg_pull.runner_id)["endpoint"] == "https://moved.example"
    assert st.get_runner(reg_pull.runner_id)["first_seen"] == 1000

    # push runner registers again
    fc.cells = [c_pull2, c_opt, c_push]
    res = registry.sync_registrations(st, fc, cfg, now=4000)
    assert res["updated"] == [reg_push.runner_id]
    assert st.get_runner(reg_push.runner_id)["status"] == "active"


def test_sync_allows_http_when_configured(tmp_path):
    fc = FakeChain()
    c_http, reg = make_registration_cell(sk(5), sk(105), endpoint="http://127.0.0.1:18080")
    fc.cells = [c_http]
    cfg = make_config(tmp_path, allow_insecure_endpoints="true")
    st = store_mod.Store(cfg.db_path)
    assert registry.sync_registrations(st, fc, cfg, now=1)["added"] == [reg.runner_id]


def test_sync_disabled_without_code_hash(tmp_path):
    fc = FakeChain()
    fc.fail = True  # must not even be called
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    cfg = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(cfg.db_path)
    assert registry.sync_registrations(st, fc, cfg, now=1) == \
        {"added": [], "updated": [], "removed": [], "invalid": 0}


def test_sync_via_rpc(tmp_path):
    fc = FakeChain()
    c1, reg = make_registration_cell(sk(1), sk(101))
    fc.cells = [c1]
    cfg = make_config(tmp_path)
    st = store_mod.Store(cfg.db_path)
    with FakeRpcServer(fc) as srv:
        res = registry.sync_registrations(st, chain_mod.RpcChain(srv.url), cfg, now=5)
    assert res["added"] == [reg.runner_id]


# ---------- tip cross-check ----------

def test_crosscheck():
    local, remote = FakeChain(tip=1000), FakeChain(tip=1005)
    cc = chain_mod.TipCrossCheck(local, remote, threshold=10)
    assert cc.check() is True
    remote.tip_number = 1011
    assert cc.check() is False
    remote.tip_number = 989
    assert cc.check() is False
    remote.tip_number = 990
    assert cc.check() is True
    remote.fail = True
    assert cc.check() is True        # second source down: cannot judge, do not pause
    remote.fail = False
    local.fail = True
    assert cc.check() is False       # own node down: pause
    assert chain_mod.TipCrossCheck(FakeChain(), None, threshold=10).check() is True
