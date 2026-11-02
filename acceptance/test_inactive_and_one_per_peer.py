"""D45 (inactive and hidden runners) and D46 (one runner per peer ID).

D45: no ok probe for `inactive_after_days` (default 3) -> inactive: listed with unranked_reason "inactive",
not ranked, not in runner_count / the gate / the epoch leaves; no ok probe for `hidden_after_days`
(default 30) -> left out of every list and total. The next ok probe brings the runner back; its history
stays. D46: several runners with the same peer ID count as one node: only the primary is listed.
"""
import sqlite3

import pytest

from csrmon import api as api_mod, config as config_mod, crypto, epochs, protocol, scoring, store as store_mod
from csrmon.hashing import to_hex
from csrmon.store import add_days, day_of
from fakes import FakeChain

MON = (0x52).to_bytes(32, "big")
NOW = 1_792_281_600
DAY = 86400
PEER = {n: "Qm" + chr(64 + n) * 44 for n in range(1, 10)}


def sk(n):
    return n.to_bytes(32, "big")


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


def rid(n):
    return protocol.runner_id(crypto.pubkey_from_secret(sk(n)))


def make_env(tmp_path, extra=(), now=NOW):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"', *extra]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    st.set_meta("monitor_start", str(NOW - 60 * DAY))
    return {"c": c, "st": st, "api": api_mod.Api(st, c, MON, clock=lambda: now)}


@pytest.fixture
def env(tmp_path):
    return make_env(tmp_path)


def add_runner(env, n, *, peer=None, age_days=40, last_ok_days_ago=0.01, slot=None, country="DE"):
    """A runner first seen `age_days` ago whose last ok probe (and last day of ok daily stats) was
    `last_ok_days_ago` days ago."""
    st = env["st"]
    st.upsert_runner(rid(n), service_pubkey=pk(n), peer_id=peer or PEER[n], p2p_pubkey="", reg_outpoint="",
                     mode="inbound", endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=True,
                     now=NOW - age_days * DAY)
    last = NOW - int(last_ok_days_ago * DAY)
    st.record_probe(rid(n), ts=last, slot=slot if slot is not None else n * 1000, mode="inbound",
                    result="ok", lag=1, in_sync=True, country=country, asn=3320 + n,
                    loc_lat=52, loc_lon=12)
    con = sqlite3.connect(env["c"].db_path)
    last_day = day_of(last)
    first = max(0, int(age_days) - 1)
    for d in range(first + 1):
        day = add_days(day_of(NOW), -d)
        ok = 140 if day <= last_day else 0
        con.execute("insert or replace into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                    " p2p_total, p2p_ok, median_lag, median_peers, score) values (?,?,?,?,?,?,?,?,?,null)",
                    (rid(n), day, 144, ok, ok, 0, 0, 1, None))
    con.commit()
    con.close()


def ranking(env, now=NOW):
    c = env["c"]
    return scoring.rank_runners(env["st"], day_of(now), c.provisional_days, now=now,
                                **scoring.activity_days(c))


def by_id(items):
    return {i["runner_id"]: i for i in items}


# ---- config ----

def test_config_defaults_and_validation(tmp_path):
    c = make_env(tmp_path)["c"]
    assert c.inactive_after_days == 3 and c.hidden_after_days == 30
    with pytest.raises(config_mod.ConfigError):
        make_env(tmp_path, ['inactive_after_days = 5', 'hidden_after_days = 4'])
    with pytest.raises(config_mod.ConfigError):
        make_env(tmp_path, ['inactive_after_days = 0'])
    c = make_env(tmp_path, ['inactive_after_days = 2', 'hidden_after_days = 10'])["c"]
    assert (c.inactive_after_days, c.hidden_after_days) == (2, 10)


def test_activity_thresholds():
    r = {"last_seen": NOW - 2 * DAY, "first_seen": NOW - 40 * DAY}
    assert scoring.activity(r, NOW) == "live"
    assert scoring.activity({**r, "last_seen": NOW - 4 * DAY}, NOW) == "inactive"
    assert scoring.activity({**r, "last_seen": NOW - 31 * DAY}, NOW) == "hidden"
    # never an ok probe: counted from first_seen
    assert scoring.activity({"last_seen": None, "first_seen": NOW - DAY}, NOW) == "live"
    assert scoring.activity({"last_seen": None, "first_seen": NOW - 5 * DAY}, NOW) == "inactive"
    # an ok day in the daily stats counts as activity too
    assert scoring.activity({"last_seen": None, "first_seen": NOW - 40 * DAY}, NOW,
                            last_ok_day=day_of(NOW)) == "live"


# ---- D45 ----

def test_inactive_is_listed_but_not_ranked_or_counted(env):
    add_runner(env, 1)
    add_runner(env, 2)
    add_runner(env, 3, last_ok_days_ago=5)
    items = by_id(ranking(env))
    assert items[rid(3)]["unranked_reason"] == "inactive" and items[rid(3)]["rank"] is None
    assert items[rid(1)]["rank"] is not None and items[rid(2)]["rank"] is not None
    s = scoring.network_summary(env["st"], day_of(NOW), env["c"], list(items.values()))
    assert s["runner_count"] == 2 and s["inactive_count"] == 1
    assert s["excluded_count"] == 0 and s["gate"]["runners"] == 2
    page = env["api"]._runners({}, day_of(NOW))
    row = next(i for i in page["items"] if i["runner_id"] == rid(3))
    assert row["unranked_reason"] == "inactive" and row["last_seen"] is not None
    # until hidden it still counts in the network totals and on the map
    assert env["api"]._build_network()["nodes_total"] == 3
    assert env["api"]._build_locations()["located"] == 3


def test_inactive_beats_provisional(env):
    add_runner(env, 1, age_days=5, last_ok_days_ago=4)
    item = ranking(env)[0]
    assert item["provisional"] and item["unranked_reason"] == "inactive"
    s = scoring.network_summary(env["st"], day_of(NOW), env["c"], [item])
    assert s["provisional_count"] == 0 and s["inactive_count"] == 1


def test_hidden_is_left_out_everywhere(env):
    add_runner(env, 1)
    add_runner(env, 2, last_ok_days_ago=31)
    assert rid(2) not in by_id(ranking(env))
    assert env["api"]._build_network()["nodes_total"] == 1
    assert env["api"]._build_locations()["located"] == 1
    # history is kept
    assert env["st"].get_runner(rid(2)) is not None
    assert env["st"].daily_stats(rid(2), add_days(day_of(NOW), -60), day_of(NOW))


def test_next_ok_probe_brings_it_back(env):
    add_runner(env, 1, last_ok_days_ago=31)
    assert ranking(env) == []
    env["st"].record_probe(rid(1), ts=NOW - 60, slot=999_999, mode="inbound", result="ok", lag=1,
                           in_sync=True)
    items = ranking(env)
    assert [i["runner_id"] for i in items] == [rid(1)]
    assert items[0]["unranked_reason"] is None and items[0]["age_days"] >= 39


def test_failed_probes_do_not_count_as_activity(env):
    add_runner(env, 1, last_ok_days_ago=4)
    env["st"].record_probe(rid(1), ts=NOW - 60, slot=888_888, mode="inbound", result="fail",
                           failure_reason="timeout")
    assert ranking(env)[0]["unranked_reason"] == "inactive"


def test_configured_days_are_used(tmp_path):
    env = make_env(tmp_path, ['inactive_after_days = 1', 'hidden_after_days = 2'])
    add_runner(env, 1, last_ok_days_ago=1.5)
    add_runner(env, 2, last_ok_days_ago=2.5)
    items = by_id(ranking(env))
    assert items[rid(1)]["unranked_reason"] == "inactive" and rid(2) not in items


def test_epoch_leaves_leave_out_inactive_runners(env):
    add_runner(env, 1, age_days=60)
    add_runner(env, 2, age_days=60, last_ok_days_ago=5)
    start, end = epochs.epoch_bounds(int(float(env["st"].get_meta("monitor_start"))), 1)
    st, c = env["st"], env["c"]
    # move both runners' activity relative to the epoch end
    con = sqlite3.connect(c.db_path)
    con.execute("update runners set first_seen=?, last_seen=? where runner_id=?", (start - 30 * DAY, end - 600, rid(1)))
    con.execute("update runners set first_seen=?, last_seen=? where runner_id=?", (start - 30 * DAY, end - 5 * DAY, rid(2)))
    con.execute("delete from daily_stats")
    con.commit()
    con.close()
    summary = epochs.build_epoch(st, FakeChain(), MON, c, 1, now=end + 10)
    leaves = {e["runner_id"] for e in summary["leaves"]}
    assert rid(1) in leaves and rid(2) not in leaves


# ---- D46 ----

def test_one_runner_per_peer_oldest_live_wins(env):
    add_runner(env, 1, peer=PEER[1], age_days=40)
    add_runner(env, 2, peer=PEER[1], age_days=2)        # same node, later runner (e.g. a copied key)
    add_runner(env, 3, peer=PEER[3], age_days=40)
    items = by_id(ranking(env))
    assert rid(1) in items and rid(2) not in items and rid(3) in items
    assert env["api"]._build_network()["nodes_total"] == 2
    assert env["api"]._build_locations()["located"] == 2
    assert env["api"]._node(PEER[1], day_of(NOW))["rank"] == items[rid(1)]["rank"]


def test_inactive_primary_hands_over_to_a_live_runner(env):
    add_runner(env, 1, peer=PEER[1], age_days=40, last_ok_days_ago=5)
    add_runner(env, 2, peer=PEER[1], age_days=10)
    items = by_id(ranking(env))
    assert list(items) == [rid(2)] and items[rid(2)]["unranked_reason"] is None


def test_identity_flag_decides_between_live_runners(env):
    add_runner(env, 1, peer=PEER[1], age_days=40)
    add_runner(env, 2, peer=PEER[1], age_days=20)
    env["st"].set_flag(rid(1), "identity_mismatch", True)   # runner 2 proved the node identity last
    items = by_id(ranking(env))
    assert list(items) == [rid(2)]


def test_reachable_counts_nodes_not_runners(env):
    add_runner(env, 1, peer=PEER[1])
    add_runner(env, 2, peer=PEER[1])
    add_runner(env, 3, peer=PEER[3])
    assert env["st"].reachable_count(NOW - 3600) == 2


def test_page_shows_inactive_rows_greyed():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = open(os.path.join(root, "csrmon", "web", "app.mjs"), encoding="utf-8").read()
    fmt = open(os.path.join(root, "csrmon", "web", "format.mjs"), encoding="utf-8").read()
    css = open(os.path.join(root, "csrmon", "web", "style.css"), encoding="utf-8").read()
    assert 'unranked_reason === "inactive"' in app and 'tr.className = "inactive"' in app
    assert 'return "inactive"' in fmt and "inactive_count" in app
    assert "tr.inactive" in css
