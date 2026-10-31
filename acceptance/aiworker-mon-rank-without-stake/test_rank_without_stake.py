"""mon-rank-without-stake (D29, D36): ranking never depends on the stake; the stake stays published as
`stake_status` and as the FLAG_STAKED bit of the epoch leaves. Phase 2 gate defaults: 120 days, 20 runners."""
import json
import os
import re
import sqlite3
import tomllib

import pytest

from csrmon import api as api_mod, config as config_mod, crypto, epochs, protocol, scoring, store as store_mod
from csrmon.hashing import to_hex
from csrmon.store import add_days, day_of
from fakes import FakeChain

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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
    """rows: (peer, key n, stake out point, status, capacity, reason)."""
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


def mixed_registry(env):
    for n, peer in enumerate(("QmA", "QmB", "QmC", "QmD", "QmE", "QmF"), 1):
        add_runner(env, n, peer)
    set_registry(env, [("QmA", 1, stake_op(0xa1), "deposited", 10_000, None),
                       ("QmB", 2, stake_op(0xa2), "withdrawn", None, "spent"),
                       ("QmD", 4, stake_op(0xa4), "invalid", 9_999, "too_small"),
                       ("QmE", 5, stake_op(0xa1), "duplicate", 10_000, "stake_in_use"),
                       ("QmF", 16, stake_op(0xa6), "deposited", 10_000, None)])   # another service key


def test_flag_staked_constant():
    assert epochs.FLAG_STAKED == 8
    assert epochs.FLAG_STAKED not in (epochs.FLAG_PROVISIONAL, epochs.FLAG_IDENTITY_MISMATCH,
                                      epochs.FLAG_BAD_BINDING)


def test_every_runner_is_ranked_whatever_its_stake(env):
    mixed_registry(env)
    items = {i["runner_id"]: i for i in get(env, "/v1/testnet/runners")["items"]}
    assert len(items) == 6
    assert sorted(i["rank"] for i in items.values()) == [1, 2, 3, 4, 5, 6]
    want = {1: "deposited", 2: "withdrawn", 3: "none", 4: "invalid", 5: "duplicate", 6: "none"}
    for n, s in want.items():
        assert items[rid(n)]["stake_status"] == s, n
    # the score alone decides the order (runner n has 140 - n ok probes a day)
    assert [items[rid(n)]["rank"] for n in range(1, 7)] == [1, 2, 3, 4, 5, 6]
    assert get(env, "/v1/testnet/summary")["runner_count"] == 6


def test_rank_runners_never_gives_stake_as_reason(env):
    mixed_registry(env)
    for req in (False, True):
        out = scoring.rank_runners(env["st"], day_of(NOW), 7, req)
        assert len(out) == 6
        assert all(i["rank"] is not None for i in out), req
        assert all(i["unranked_reason"] is None for i in out), req
        assert {i["stake_status"] for i in out} == {"deposited", "withdrawn", "none", "invalid", "duplicate"}


def test_other_reasons_still_unrank(env):
    add_runner(env, 1, "QmA")
    add_runner(env, 2, "QmB", age_days=2)              # provisional
    set_registry(env, [("QmA", 1, stake_op(0xa1), "deposited", 10_000, None)])
    r = {i["runner_id"]: i for i in scoring.rank_runners(env["st"], day_of(NOW), 7, True)}
    assert r[rid(1)]["rank"] == 1
    assert r[rid(2)]["rank"] is None and r[rid(2)]["unranked_reason"] == "provisional"


def test_node_endpoint_ranks_an_unregistered_node(env):
    add_runner(env, 1, "QmA")
    add_runner(env, 2, "QmB")
    set_registry(env, [("QmA", 1, stake_op(0xa1), "deposited", 10_000, None)])
    node = get(env, "/v1/nodes/QmB")
    assert node["rank"] is not None
    assert node["stake"]["status"] == "none"


def test_epoch_leaves_include_unstaked_runners_with_flag(env):
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
    leaves = {l["runner_id"]: l for l in summary["leaves"]}
    assert set(leaves) == {rid(1), rid(2), rid(3)}
    assert summary["runner_count"] == 3
    assert leaves[rid(1)]["flags"] & epochs.FLAG_STAKED
    assert not leaves[rid(2)]["flags"] & epochs.FLAG_STAKED
    assert not leaves[rid(3)]["flags"] & epochs.FLAG_STAKED
    assert epochs.decode_leaf(bytes.fromhex(leaves[rid(1)]["leaf_hex"][2:]))["flags"] & epochs.FLAG_STAKED


def test_without_registry_config_no_leaf_is_staked(tmp_path):
    env = make_env(tmp_path, registry=False)
    st = env["st"]
    add_runner(env, 1, "QmA")
    add_runner(env, 2, "QmB")
    assert sorted(i["rank"] for i in get(env, "/v1/testnet/runners")["items"]) == [1, 2]
    start = int(float(st.get_meta("monitor_start")))
    n = epochs.epoch_at(start, NOW) - 1
    epochs.build_pending(st, FakeChain(tip=12_000_000), MON, env["c"], now=NOW)
    leaves = st.get_epoch(n)["summary"]["leaves"]
    assert len(leaves) == 2
    assert all(not l["flags"] & epochs.FLAG_STAKED for l in leaves)


def test_gate_defaults_are_120_days_and_20_runners(env):
    c = env["c"]
    assert c.gate_min_days == 120
    assert c.gate_min_runners == 20
    assert c.gate_max_asn_share == 0.25 and c.gate_max_country_share == 0.5
    for name in ("monitor-mainnet.toml", "monitor-testnet.toml"):
        with open(os.path.join(ROOT, "config", name), "rb") as f:
            t = tomllib.load(f)
        assert t["gate_min_days"] == 120, name
        assert t["gate_min_runners"] == 20, name


def test_gate_progress_uses_the_new_defaults(env):
    for n, peer in enumerate(("QmA", "QmB"), 1):
        add_runner(env, n, peer)
    gate = get(env, "/v1/testnet/summary")["gate"]
    assert gate["min_days"] == 120 and gate["min_runners"] == 20
    assert gate["met"] is False
    assert gate["progress"] == round(min(1, gate["history_days"] / 120, 2 / 20), 4)


def test_protocol_doc_describes_the_new_rule():
    with open(os.path.join(ROOT, "docs", "PROTOCOL.md"), encoding="utf-8") as f:
        doc = f.read()
    assert "FLAG_STAKED" in doc
    assert "left out of the epoch leaves" not in doc
    assert not re.search(r"only runners whose registry cell has stake status `deposited`[^.]*are ranked", doc)
    with open(os.path.join(ROOT, "DECISIONS.md"), encoding="utf-8") as f:
        assert "D29" in f.read()
