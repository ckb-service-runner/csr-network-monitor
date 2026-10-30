"""mon-ops-robustness: failure paths of the daemon, the stat cell publishing and the tip cross-check."""
import threading
import time
from types import SimpleNamespace

import pytest

from csrmon import chain as chain_mod, daemon as daemon_mod, epochs, stat_cell, store as store_mod
from csrmon.hashing import blake160, to_hex
from csrmon import crypto
from fakes import FakeChain, cell
from test_mon_ops import make_config

MON = (0x51).to_bytes(32, "big")
CKB = 10 ** 8


def test_failing_task_does_not_stop_the_others(tmp_path):
    d = daemon_mod.Daemon(make_config(tmp_path))
    ran = threading.Event()
    stopper = {}

    def setup():
        d.store = SimpleNamespace(close=lambda: None)
        d.server = SimpleNamespace(stop=lambda: None)
        d.prober = SimpleNamespace(run_due=lambda: None, paused=False)
        d.p2p = None
        d.chain = SimpleNamespace(get_peers=lambda: [])
        d.discovery = SimpleNamespace(due=lambda p, n: [])
    d._setup = setup
    d._sync = lambda now: (_ for _ in ()).throw(RuntimeError("sync broke"))
    d._epochs = lambda now: (_ for _ in ()).throw(RuntimeError("epochs broke"))
    d._aggregate = lambda now: ran.set()
    t = threading.Thread(target=d.run, daemon=True)
    t.start()
    assert ran.wait(10), "aggregate must still run after other tasks raised"
    d.stop()
    t.join(10)
    assert not t.is_alive()


class TxChain(FakeChain):
    """A fake chain that knows transaction statuses."""
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.status = {}

    def get_transaction(self, tx_hash):
        return {"status": self.status.get(tx_hash, "unknown"), "block": None}


@pytest.fixture
def env(tmp_path):
    ACP = "0x" + "ac" * 32
    c = make_config(tmp_path, stat_cell_enabled=True, stat_cell_acp_code_hash=ACP,
                    stat_cell_acp_dep_tx="0x" + "de" * 32, stat_cell_sighash_dep_tx="0x" + "5d" * 32)
    st = store_mod.Store(c.db_path)
    start = 1_791_763_200 - 4 * epochs.EPOCH_SECONDS
    st.set_meta("monitor_start", str(start))
    fc = TxChain(tip=12_000_000)
    now = start + 3 * epochs.EPOCH_SECONDS + 10
    epochs.build_pending(st, fc, MON, c, now=now)
    funding = {"code_hash": c.stat_cell_sighash_code_hash, "hash_type": "type",
               "args": to_hex(blake160(crypto.pubkey_from_secret(MON)))}
    fc.cells = [cell(None, "0x", "0x" + "f1" * 32, 0, capacity=900 * CKB, lock=funding)]
    return {"c": c, "st": st, "fc": fc, "now": now}


def run_epochs(env):
    d = daemon_mod.Daemon(env["c"])
    d.store, d.chain, d.secret = env["st"], env["fc"], MON
    d.writer = stat_cell.StatCellWriter(env["st"], env["fc"], env["c"], MON)
    d._epochs(env["now"])
    return d


def test_epochs_get_built_with_time_and_in_order(env):
    summaries = [e["summary"] for e in env["st"].list_epochs()]
    assert [s["epoch"] for s in summaries] == [1, 2, 3]
    assert all(s["built_at"] == env["now"] for s in summaries)
    assert [s["late"] for s in summaries] == [True, True, False]    # 1 day after the end counts as late


def test_dropped_transaction_is_sent_again(env):
    st, fc = env["st"], env["fc"]
    run_epochs(env)
    assert len(fc.sent) == 1
    first = st.get_epoch(3)["stat_cell_tx"]
    assert first, "newest epoch goes first"
    assert [e["superseded"] for e in st.epoch_states()] == [True, True, False]
    run_epochs(env)                                  # unknown, tip unchanged: wait
    assert len(fc.sent) == 1
    fc.tip = lambda: (12_000_000 + stat_cell.RESEND_AFTER_BLOCKS, "0x" + "00" * 32)
    run_epochs(env)                                  # dropped: confirm clears, same pass resends
    assert len(fc.sent) == 2


def test_committed_transaction_is_published(env):
    st, fc = env["st"], env["fc"]
    run_epochs(env)
    fc.status[st.get_epoch(3)["stat_cell_tx"]] = "committed"
    run_epochs(env)
    assert st.epoch_states()[-1]["published"] is True
    assert len(fc.sent) == 1


def test_second_source_failure_is_unknown_and_does_not_pause():
    class Tip:
        def __init__(self, n):
            self.n = n

        def tip(self):
            if self.n is None:
                raise chain_mod.RpcError("down")
            return self.n, "0x00"
    remote = Tip(None)
    cc = chain_mod.TipCrossCheck(Tip(100), remote, 10)
    assert cc.check() is True and cc.status == "unknown"
    assert cc.check() is True and cc.status == "unknown"
    remote.n = 150
    assert cc.check() is False and cc.status == "diverged"
    remote.n = 101
    assert cc.check() is True and cc.status == "ok"
