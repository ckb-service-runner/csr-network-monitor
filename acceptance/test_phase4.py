"""Phase 4 acceptance: node RPC client, registration discovery, tip cross-check."""
import socket

import pytest

from csrmon import chain as chain_mod, store as store_mod, config as config_mod, protocol, crypto
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
