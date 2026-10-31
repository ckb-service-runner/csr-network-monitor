"""Metrics, score_v1, ranking and network summary (all from daily_stats)."""
import statistics

from .store import add_days, day_of, day_start

SCORE_FORMULA = "score_v1"
# score_v1 is frozen: any change to the weights or the terms needs score_v2 and a new formula
# byte in the epoch. The peer-count term P was dropped (D11 B, D18 A); its 5 % went to A30.
WEIGHTS = {"a30": 0.45, "a365": 0.15, "s30": 0.15, "f30": 0.15, "t": 0.10}
_BAD_FLAGS = ("identity_mismatch", "bad_binding")
IDENTITY_PROOF_MAX_AGE_S = 7 * 86400


def _days_between(a, b) -> int:
    return (day_start(b) - day_start(a)) // 86400


def _ratio(a, b) -> float:
    return a / b if b else 0.0


def runner_metrics(store, runner_id, today, provisional_days=7, runner=None) -> dict:
    if runner is None:
        runner = store.get_runner(runner_id)
    rows = store.daily_stats(runner_id, add_days(today, -364), today)
    cut30 = add_days(today, -29)
    cut7 = add_days(today, -6)
    r30 = [r for r in rows if r["day"] >= cut30]
    r7 = [r for r in rows if r["day"] >= cut7]

    def acc(rs):
        return _ratio(sum(r["probes_ok"] for r in rs), sum(r["probes_total"] for r in rs))

    a7, a30, a365 = acc(r7), acc(r30), acc(rows)
    s30 = _ratio(sum(r["in_sync"] for r in r30), sum(r["probes_ok"] for r in r30))
    f30 = _ratio(sum(r["p2p_ok"] for r in r30), sum(r["p2p_total"] for r in r30))
    age_days = max(0, _days_between(day_of(runner["first_seen"]), today))
    t = min(1.0, age_days / 365)
    lags = [r["median_lag"] for r in r30 if r["median_lag"] is not None]
    m = {"a7": a7, "a30": a30, "a365": a365, "s30": s30, "f30": f30, "t": t,
         "median_lag_30": statistics.median(lags) if lags else None,
         "age_days": age_days, "provisional": age_days < provisional_days}
    if any(f in runner["flags"] for f in _BAD_FLAGS):
        m["score"] = 0.0
    else:
        m["score"] = round(100 * sum(w * m[k] for k, w in WEIGHTS.items()), 2)
    return m


def stake_required(config) -> bool:
    return bool(config.csr_registry_code_hash and config.config_type_args)


def _stake_status(store, runner) -> str:
    row = store.stake_for(runner["peer_id"])
    if row and str(row["service_pubkey"]).lower() == str(runner["service_pubkey"] or "").lower():
        return row["status"]
    return "none"


def identity_ok(runner, *, require, now) -> bool:
    """True when proofs are not required, else when the runner proved its node's P2P key within 7 days."""
    if not require:
        return True
    at = runner.get("identity_proven_at")
    return at is not None and now - at <= IDENTITY_PROOF_MAX_AGE_S


def unranked_reason(item):
    if item["provisional"]:
        return "provisional"
    if any(f in item["flags"] for f in _BAD_FLAGS):
        return "flagged"
    if not item["identity_ok"]:
        return "identity_unproven"
    return None


def rank_runners(store, today, provisional_days=7, require_stake=False, *, require_identity=False,
                 now=None) -> list:
    if now is None:
        now = day_start(today) + 86400 - 1
    items = []
    for r in store.list_runners(("active",)):
        m = runner_metrics(store, r["runner_id"], today, provisional_days, runner=r)
        m.update(runner_id=r["runner_id"], rank=None, status=r["status"], flags=list(r["flags"]),
                 country=r["country"], region=r["region"], asn=r["asn"],
                 first_seen=r["first_seen"], stake_status=_stake_status(store, r),
                 stake_required=require_stake, identity_proven_at=r.get("identity_proven_at"),
                 identity_ok=identity_ok(r, require=require_identity, now=now))
        m["unranked_reason"] = unranked_reason(m)
        items.append(m)
    ranked = [i for i in items if i["unranked_reason"] is None]
    ranked.sort(key=lambda i: (-i["score"], i["first_seen"], i["runner_id"]))
    for n, i in enumerate(ranked, 1):
        i["rank"] = n
    unranked = [i for i in items if i["rank"] is None]
    unranked.sort(key=lambda i: (-i["score"], i["runner_id"]))
    asn_count = {}
    for i in ranked:
        if i["asn"]:
            asn_count[i["asn"]] = asn_count.get(i["asn"], 0) + 1
    out = ranked + unranked
    for i in out:
        if not i["asn"]:
            i["asn_peers"] = 0
        else:
            i["asn_peers"] = asn_count.get(i["asn"], 0) - (1 if i["rank"] is not None else 0)
    return out


def update_scores(store, today, provisional_days=7, require_stake=False, *, require_identity=False,
                  now=None) -> list:
    ranking = rank_runners(store, today, provisional_days, require_stake,
                           require_identity=require_identity, now=now)
    for i in ranking:
        store.set_daily_score(i["runner_id"], today, i["score"])
    return ranking


def diversity_index(counts: dict) -> float:
    total = sum(counts.values())
    if not total:
        return 0.0
    return round(1 - sum((c / total) ** 2 for c in counts.values()), 4)


def _count(items, key, default):
    out = {}
    for i in items:
        k = i[key]
        k = default if k is None or k == "" else str(k)
        out[k] = out.get(k, 0) + 1
    return out


def _largest_share(counts) -> float:
    total = sum(counts.values())
    return round(max(counts.values()) / total, 4) if total else 0.0


def network_summary(store, today, config, ranking=None) -> dict:
    if ranking is None:
        ranking = rank_runners(store, today, config.provisional_days, stake_required(config),
                               require_identity=getattr(config, "require_identity_proof", False))
    ranked = [i for i in ranking if i["rank"] is not None]
    provisional = sum(1 for i in ranking if i["provisional"])
    excluded = sum(1 for i in ranking if i["rank"] is None and not i["provisional"])
    by_country = _count(ranked, "country", "??")
    by_region = _count(ranked, "region", "??")
    by_asn = _count(ranked, "asn", "0")
    asn_share = _largest_share(by_asn)
    country_share = _largest_share(by_country)
    start = store.get_meta("monitor_start")
    history_days = max(0, _days_between(day_of(int(float(start))), today)) if start else 0
    n = len(ranked)
    g_days, g_runners = config.gate_min_days, config.gate_min_runners
    met = (n > 0 and history_days >= g_days and n >= g_runners
           and asn_share <= config.gate_max_asn_share
           and country_share <= config.gate_max_country_share)
    progress = round(min(1, history_days / g_days, n / g_runners), 4)
    return {
        "network": config.network, "date": today, "score_formula": SCORE_FORMULA,
        "runner_count": n, "provisional_count": provisional, "excluded_count": excluded,
        "by_country": by_country, "by_region": by_region, "by_asn": by_asn,
        "largest_asn_share": asn_share, "largest_country_share": country_share,
        "diversity_index": diversity_index(by_asn),
        "country_diversity_index": diversity_index(by_country),
        "gate": {"history_days": history_days, "min_days": g_days, "runners": n,
                 "min_runners": g_runners, "largest_asn_share": asn_share,
                 "max_asn_share": config.gate_max_asn_share,
                 "largest_country_share": country_share,
                 "max_country_share": config.gate_max_country_share,
                 "met": met, "progress": progress},
    }
