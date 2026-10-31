"""Phase 7 acceptance: metrics, score_v1, ranking, network summary."""
import sqlite3
import statistics

import pytest

from csrmon import scoring, store as store_mod, config as config_mod

TODAY = "2026-10-18"


def rid(n):
    return "0x" + f"{n:064x}"


def setup(tmp_path, **cfg_extra):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    lines += [f"{k} = {v}" for k, v in cfg_extra.items()]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    cfg = config_mod.load_config(str(tmp_path / "c.toml"))
    return cfg, store_mod.Store(cfg.db_path)


def add(st, n, age_days, country="DE", asn=3320, status=None, flags=()):
    first = store_mod.day_start(store_mod.add_days(TODAY, -age_days)) + 3600
    st.upsert_runner(rid(n), service_pubkey="0x02", peer_id=f"Qm{n}", p2p_pubkey="0x03",
                     reg_outpoint="0x00:0", mode="pull", endpoint="https://x", p2p_port=0,
                     ranking_opt_in=True, now=first)
    con = sqlite3.connect(st_path(st))
    con.execute("update runners set country=?, region=?, asn=? where runner_id=?",
                (country, {"DE": "EU", "US": "NA", "JP": "AS"}.get(country, "??"), asn, rid(n)))
    con.commit()
    con.close()
    if status:
        st.set_status(rid(n), status)
    for f in flags:
        st.set_flag(rid(n), f, True)


_paths = {}


def st_path(st):
    return _paths[id(st)]


def put_day(st, n, days_ago, total=144, ok=140, sync=130, p2p_total=1, p2p_ok=1, lag=2, peers=8):
    con = sqlite3.connect(st_path(st))
    con.execute("insert or replace into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                " p2p_total, p2p_ok, median_lag, median_peers, score) values (?,?,?,?,?,?,?,?,?,null)",
                (rid(n), store_mod.add_days(TODAY, -days_ago), total, ok, sync, p2p_total, p2p_ok,
                 lag, peers))
    con.commit()
    con.close()


@pytest.fixture
def env(tmp_path):
    cfg, st = setup(tmp_path)
    _paths[id(st)] = cfg.db_path
    return cfg, st


def expected(rows, age_days):
    """Independent score_v1 implementation over (days_ago, row) pairs."""
    def window(n):
        return [r for d, r in rows if d < n]
    def share(rs, a, b):
        tot = sum(r[b] for r in rs)
        return sum(r[a] for r in rs) / tot if tot else 0.0
    a7, a30, a365 = (share(window(n), "ok", "total") for n in (7, 30, 365))
    s30 = share(window(30), "sync", "ok")
    f30 = share(window(30), "p2p_ok", "p2p_total")
    t = min(1.0, age_days / 365)
    score = round(100 * (0.45 * a30 + 0.15 * a365 + 0.15 * s30 + 0.15 * f30 + 0.10 * t), 2)
    return dict(a7=a7, a30=a30, a365=a365, s30=s30, f30=f30, t=t, score=score)


def test_constants():
    assert scoring.SCORE_FORMULA == "score_v1"
    assert scoring.WEIGHTS == {"a30": 0.45, "a365": 0.15, "s30": 0.15, "f30": 0.15, "t": 0.10}


def test_runner_metrics_formula(env):
    cfg, st = env
    add(st, 1, age_days=100)
    rows = []
    for d in range(0, 100):
        r = dict(total=144, ok=144 - (d % 5), sync=120 + (d % 7), p2p_total=1,
                 p2p_ok=0 if d % 9 == 0 else 1, peers=4 + (d % 6), lag=d % 3)
        if d == 12:
            r.update(total=0, ok=0, sync=0, peers=None, lag=None)   # day without probes
        rows.append((d, r))
        put_day(st, 1, d, total=r["total"], ok=r["ok"], sync=r["sync"], p2p_total=r["p2p_total"],
                p2p_ok=r["p2p_ok"], lag=r["lag"], peers=r["peers"])
    put_day(st, 1, 400, total=144, ok=0)   # outside every window
    m = scoring.runner_metrics(st, rid(1), TODAY, provisional_days=7)
    e = expected(rows, 100)
    for k in ("a7", "a30", "a365", "s30", "f30", "t"):
        assert m[k] == pytest.approx(e[k], abs=1e-9), k
    assert m["score"] == e["score"]
    assert m["age_days"] == 100 and m["provisional"] is False
    lags = [r["lag"] for d, r in rows if d < 30 and r["lag"] is not None]
    assert m["median_lag_30"] == statistics.median(lags)


def test_metrics_without_data_and_provisional(env):
    cfg, st = env
    add(st, 2, age_days=3)
    m = scoring.runner_metrics(st, rid(2), TODAY, provisional_days=7)
    assert m["a7"] == m["a30"] == m["a365"] == m["s30"] == m["f30"] == 0.0
    assert m["median_lag_30"] is None
    assert m["provisional"] is True and m["age_days"] == 3
    assert m["score"] == round(100 * 0.10 * 3 / 365, 2)
    add(st, 3, age_days=7)
    assert scoring.runner_metrics(st, rid(3), TODAY, provisional_days=7)["provisional"] is False
    add(st, 4, age_days=900)
    assert scoring.runner_metrics(st, rid(4), TODAY, provisional_days=7)["t"] == 1.0


def test_flags_zero_the_score(env):
    cfg, st = env
    add(st, 1, age_days=50, flags=("identity_mismatch",))
    add(st, 2, age_days=50, flags=("bad_binding",))
    for n in (1, 2):
        for d in range(30):
            put_day(st, n, d)
        assert scoring.runner_metrics(st, rid(n), TODAY)["score"] == 0.0


def full_days(st, n, ok=140, days=30):
    for d in range(days):
        put_day(st, n, d, ok=ok, sync=min(ok, 130))


def test_rank_runners(env):
    cfg, st = env
    add(st, 1, 60, country="DE", asn=3320); full_days(st, 1, ok=140)
    add(st, 2, 60, country="US", asn=7922); full_days(st, 2, ok=144)
    add(st, 3, 80, country="DE", asn=3320); full_days(st, 3, ok=140)   # same score as 1, older
    add(st, 4, 2, country="JP", asn=2516); full_days(st, 4, ok=144, days=2)   # provisional
    add(st, 5, 60, country="DE", asn=3320, flags=("identity_mismatch",)); full_days(st, 5)
    add(st, 6, 60, status="opted_out"); full_days(st, 6)
    add(st, 7, 60, status="deregistered"); full_days(st, 7)
    # make 1 and 3 tie exactly: same stats and same age term would differ, so equalise t
    con = sqlite3.connect(st_path(st))
    first3 = con.execute("select first_seen from runners where runner_id=?", (rid(3),)).fetchone()[0]
    con.execute("update runners set first_seen=? where runner_id=?", (first3 + 1, rid(1)))
    con.commit(); con.close()
    ranking = scoring.rank_runners(st, TODAY, provisional_days=7)
    ids = [r["runner_id"] for r in ranking]
    assert rid(6) not in ids and rid(7) not in ids
    ranked = [r for r in ranking if r["rank"] is not None]
    assert [r["runner_id"] for r in ranked] == [rid(2), rid(3), rid(1)]
    assert [r["rank"] for r in ranked] == [1, 2, 3]
    assert ranked[1]["score"] == ranked[2]["score"]
    unranked = ranking[3:]
    assert {r["runner_id"] for r in unranked} == {rid(4), rid(5)}
    by = {r["runner_id"]: r for r in ranking}
    assert by[rid(4)]["provisional"] is True and by[rid(4)]["rank"] is None
    assert by[rid(5)]["score"] == 0.0 and by[rid(5)]["flags"] == ["identity_mismatch"]
    assert by[rid(1)]["asn_peers"] == 1 and by[rid(3)]["asn_peers"] == 1
    assert by[rid(2)]["asn_peers"] == 0
    assert by[rid(5)]["asn_peers"] == 2         # unranked: counts ranked runners on its ASN
    for k in ("country", "region", "asn", "status", "first_seen", "a7", "a30", "a365",
              "s30", "f30", "t", "median_lag_30", "age_days"):
        assert k in by[rid(1)]
    assert by[rid(2)]["country"] == "US" and by[rid(2)]["region"] == "NA"


def test_update_scores(env):
    cfg, st = env
    add(st, 1, 60); full_days(st, 1)
    ranking = scoring.update_scores(st, TODAY, provisional_days=7)
    [d] = st.daily_stats(rid(1), TODAY, TODAY)
    assert d["score"] == ranking[0]["score"] > 0


def test_diversity_index():
    assert scoring.diversity_index({}) == 0.0
    assert scoring.diversity_index({"a": 5}) == 0.0
    assert scoring.diversity_index({"a": 1, "b": 1}) == 0.5
    assert scoring.diversity_index({"a": 2, "b": 1, "c": 1}) == 0.625


def test_network_summary(tmp_path):
    cfg, st = setup(tmp_path, gate_min_days=10, gate_min_runners=3,
                    gate_max_asn_share=0.5, gate_max_country_share=0.7)
    _paths[id(st)] = cfg.db_path
    st.set_meta("monitor_start", str(store_mod.day_start(store_mod.add_days(TODAY, -20)) + 50))
    add(st, 1, 30, country="DE", asn=3320); full_days(st, 1)
    add(st, 2, 30, country="DE", asn=3320); full_days(st, 2)
    add(st, 3, 30, country="US", asn=7922); full_days(st, 3)
    add(st, 4, 30, country="JP", asn=2516); full_days(st, 4)
    add(st, 5, 1, country="JP", asn=2516)                       # provisional
    add(st, 6, 30, flags=("bad_binding",)); full_days(st, 6)    # excluded
    s = scoring.network_summary(st, TODAY, cfg)
    assert s["network"] == "testnet" and s["date"] == TODAY
    assert s["score_formula"] == "score_v1"
    assert s["runner_count"] == 4 and s["provisional_count"] == 1 and s["excluded_count"] == 1
    assert s["by_country"] == {"DE": 2, "US": 1, "JP": 1}
    assert s["by_region"] == {"EU": 2, "NA": 1, "AS": 1}
    assert s["by_asn"] == {"3320": 2, "7922": 1, "2516": 1}
    assert s["largest_asn_share"] == 0.5 and s["largest_country_share"] == 0.5
    assert s["diversity_index"] == 0.625 and s["country_diversity_index"] == 0.625
    g = s["gate"]
    assert g["history_days"] == 20 and g["min_days"] == 10
    assert g["runners"] == 4 and g["min_runners"] == 3
    assert g["max_asn_share"] == 0.5 and g["max_country_share"] == 0.7
    assert g["largest_asn_share"] == 0.5 and g["largest_country_share"] == 0.5
    assert g["met"] is True and g["progress"] == 1.0


def test_gate_not_met(tmp_path):
    cfg, st = setup(tmp_path)
    _paths[id(st)] = cfg.db_path
    st.set_meta("monitor_start", str(store_mod.day_start(store_mod.add_days(TODAY, -73))))
    add(st, 1, 30); full_days(st, 1)
    s = scoring.network_summary(st, TODAY, cfg)
    g = s["gate"]
    assert g["history_days"] == 73 and g["runners"] == 1 and g["met"] is False
    assert g["progress"] == round(1 / 20, 4)
    assert s["largest_asn_share"] == 1.0


def test_summary_empty_network(tmp_path):
    cfg, st = setup(tmp_path)
    s = scoring.network_summary(st, TODAY, cfg)
    assert s["runner_count"] == 0 and s["by_country"] == {} and s["diversity_index"] == 0.0
    assert s["largest_asn_share"] == 0.0 and s["gate"]["history_days"] == 0
    assert s["gate"]["met"] is False and s["gate"]["progress"] == 0.0
