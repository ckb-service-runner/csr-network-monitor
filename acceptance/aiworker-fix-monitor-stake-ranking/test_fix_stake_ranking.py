"""fix-monitor-stake-ranking, phase 2: only runners with a deposited registry stake are ranked
(F-MON-001, F-MON-002, F-MON-003)."""
import json
import sqlite3

import pytest

from csrmon import api as api_mod, crypto, epochs, protocol, scoring, store as store_mod, config as config_mod
from csrmon.hashing import to_hex
from csrmon.store import add_days, day_of
from fakes import FakeChain

MON = (0x51).to_bytes(32, "big")
CONFIG_ARGS = "0x" + "a9" * 32
REGISTRY_CODE = "0x" + "47" * 32
NOW = 1_792_281_600
EXP = NOW * 1000 + 7 * 86400000


def sk(n):
    return n.to_bytes(32, "big")


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


def rid(n):
    return protocol.runner_id(crypto.pubkey_from_secret(sk(n)))


def stake_op(b):
    return "0x" + f"{b:02x}" * 32 + ":0"


def make_env(tmp_path, registry=True):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    if registry:
        lines += [f'config_type_args = "{CONFIG_ARGS}"', f'csr_registry_code_hash = "{REGISTRY_CODE}"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    st.set_meta("monitor_start", str(NOW - 60 * 86400))
    return {"c": c, "st": st, "api": api_mod.Api(st, c, MON, clock=lambda: NOW)}


@pytest.fixture
def env(tmp_path):
    return make_env(tmp_path)


def add_runner(env, n, peer, *, age_days=40, ok_days=30):
    st = env["st"]
    st.upsert_runner(rid(n), service_pubkey=pk(n), peer_id=peer, p2p_pubkey="", reg_outpoint="",
                     mode="inbound", endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=True,
                     now=NOW - age_days * 86400)
    st.record_probe(rid(n), ts=NOW - 600, slot=n * 1000, mode="inbound", result="ok", lag=1, in_sync=True,
                    country="DE", asn=3320 + n)
    con = sqlite3.connect(env["c"].db_path)
    for d in range(ok_days):
        con.execute("insert or replace into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                    " p2p_total, p2p_ok, median_lag, median_peers, score) values (?,?,?,?,?,?,?,?,?,null)",
                    (rid(n), add_days(day_of(NOW), -d), 144, 140 - n, 130, 0, 0, 1, None))
    con.commit()
    con.close()


def set_registry(env, rows):
    """Writes what a registry scan writes. rows: (peer, key n, stake out point, status, capacity, reason)."""
    st = env["st"]
    reg = lambda i: "0x" + f"{i + 1:02x}" * 32 + ":0"
    st.set_stakes([{"peer_id": p, "service_pubkey": pk(n), "reg_outpoint": reg(i), "expiry_ms": EXP,
                    "stake_outpoint": s, "status": status, "capacity_ckb": cap, "reason": reason}
                   for i, (p, n, s, status, cap, reason) in enumerate(rows)])
    st.set_registrations([{"peer_id": p, "service_pubkey": pk(n), "expiry_ms": EXP, "outpoint": reg(i)}
                          for i, (p, n, s, status, cap, reason) in enumerate(rows) if status == "deposited"])


def get(env, path):
    status, _, data = env["api"].handle("GET", path, {}, b"", "10.0.0.1")
    assert status == 200, data
    return json.loads(data)


def ranking(env):
    out = scoring.rank_runners(env["st"], day_of(NOW), 7, require_stake=True)
    return {i["runner_id"]: i for i in out}


def test_stake_required_follows_the_registry_config(env, tmp_path):
    assert scoring.stake_required(env["c"]) is True
    sub = tmp_path / "plain"
    sub.mkdir()
    assert scoring.stake_required(make_env(sub, registry=False)["c"]) is False


def test_only_deposited_registrations_are_ranked(env):
    for n, peer in enumerate(("QmA", "QmB", "QmC", "QmD", "QmE", "QmF"), 1):
        add_runner(env, n, peer)
    set_registry(env, [("QmA", 1, stake_op(0xa1), "deposited", 10_000, None),
                       ("QmB", 2, stake_op(0xa2), "withdrawn", None, "spent"),
                       ("QmD", 4, stake_op(0xa4), "invalid", 9_999, "too_small"),
                       ("QmE", 5, stake_op(0xa1), "duplicate", 10_000, "stake_in_use"),
                       ("QmF", 16, stake_op(0xa6), "deposited", 10_000, None)])   # another service key
    items = {i["runner_id"]: i for i in get(env, "/v1/testnet/runners")["items"]}
    assert len(items) == 6
    assert items[rid(1)]["rank"] == 1 and items[rid(1)]["stake_status"] == "deposited"
    want = {2: "withdrawn", 3: "none", 4: "invalid", 5: "duplicate", 6: "none"}
    for n, s in want.items():
        assert items[rid(n)]["rank"] is None, n
        assert items[rid(n)]["stake_status"] == s, n
        assert items[rid(n)]["status"] == "active", n          # the runner row itself is not changed
    assert get(env, "/v1/testnet/summary")["runner_count"] == 1


def test_withdrawal_or_destroyed_cell_removes_the_rank_at_the_next_scan(env):
    add_runner(env, 1, "QmA")
    add_runner(env, 2, "QmB")
    set_registry(env, [("QmA", 1, stake_op(0xa1), "deposited", 10_000, None),
                       ("QmB", 2, stake_op(0xa2), "deposited", 10_000, None)])
    r = ranking(env)
    assert r[rid(1)]["rank"] is not None and r[rid(2)]["rank"] is not None
    set_registry(env, [("QmA", 1, stake_op(0xa1), "deposited", 10_000, None),
                       ("QmB", 2, stake_op(0xa2), "withdrawn", None, "spent")])
    r = ranking(env)
    assert r[rid(1)]["rank"] == 1
    assert r[rid(2)]["rank"] is None and r[rid(2)]["stake_status"] == "withdrawn"
    assert env["st"].get_runner(rid(2))["status"] == "active"
    set_registry(env, [])                                     # both registry cells destroyed
    r = ranking(env)
    assert len(r) == 2
    assert all(i["rank"] is None for i in r.values())
    assert {i["stake_status"] for i in r.values()} == {"none"}


def test_without_registry_config_everybody_is_ranked_as_before(tmp_path):
    env = make_env(tmp_path, registry=False)
    add_runner(env, 1, "QmA")
    add_runner(env, 2, "QmB")
    items = get(env, "/v1/testnet/runners")["items"]
    assert sorted(i["rank"] for i in items) == [1, 2]
    assert {i["stake_status"] for i in items} == {"none"}
    assert get(env, "/v1/testnet/summary")["runner_count"] == 2


def test_epoch_leaves_only_for_deposited_registrations(env):
    st = env["st"]
    add_runner(env, 1, "QmA")
    add_runner(env, 2, "QmB")
    add_runner(env, 3, "QmC")
    set_registry(env, [("QmA", 1, stake_op(0xa1), "deposited", 10_000, None),
                       ("QmB", 2, stake_op(0xa2), "withdrawn", None, "spent")])
    start = int(float(st.get_meta("monitor_start")))
    n = epochs.epoch_at(start, NOW) - 1
    assert n >= 1 and epochs.epoch_bounds(start, n)[1] <= NOW
    built = epochs.build_pending(st, FakeChain(tip=12_000_000), MON, env["c"], now=NOW)
    assert n in built
    summary = st.get_epoch(n)["summary"]
    assert [l["runner_id"] for l in summary["leaves"]] == [rid(1)]
    assert summary["runner_count"] == 1
