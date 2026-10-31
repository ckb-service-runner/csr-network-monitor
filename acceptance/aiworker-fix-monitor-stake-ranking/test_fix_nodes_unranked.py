"""fix-monitor-stake-ranking, phase 1: GET /v1/nodes/{peer_id} answers 200 for unranked runners (F-MON-004)."""
import json
import os
import sqlite3

import pytest

from csrmon import api as api_mod, crypto, protocol, store as store_mod, config as config_mod
from csrmon.hashing import to_hex
from csrmon.store import add_days, day_of

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MON = (0x51).to_bytes(32, "big")
CONFIG_ARGS = "0x" + "a9" * 32
REGISTRY_CODE = "0x" + "47" * 32
NOW = 1_792_281_600
EXP = NOW * 1000 + 7 * 86400000
# Integration (Oct 2026): plus score and metrics (score_v1 terms) for the runner dashboard.
KEYS = {"peer_id", "rank", "of", "provisional", "availability", "check_type", "attestation", "stake",
        "last_check_at", "score", "metrics"}


def sk(n):
    return n.to_bytes(32, "big")


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


def rid(n):
    return protocol.runner_id(crypto.pubkey_from_secret(sk(n)))


def stake_op(b):
    return "0x" + f"{b:02x}" * 32 + ":0"


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"',
             f'config_type_args = "{CONFIG_ARGS}"', f'csr_registry_code_hash = "{REGISTRY_CODE}"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    st.set_meta("monitor_start", str(NOW - 60 * 86400))
    return {"c": c, "st": st, "api": api_mod.Api(st, c, MON, clock=lambda: NOW)}


def add_runner(env, n, peer, *, age_days=40, ok_days=30, flags=()):
    st = env["st"]
    st.upsert_runner(rid(n), service_pubkey=pk(n), peer_id=peer, p2p_pubkey="", reg_outpoint="",
                     mode="inbound", endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=True,
                     now=NOW - age_days * 86400)
    st.record_probe(rid(n), ts=NOW - 600, slot=n * 1000, mode="inbound", result="ok", lag=1, in_sync=True,
                    country="DE", asn=3320)
    for f in flags:
        st.set_flag(rid(n), f, True)
    con = sqlite3.connect(env["c"].db_path)
    for d in range(ok_days):
        con.execute("insert or replace into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                    " p2p_total, p2p_ok, median_lag, median_peers, score) values (?,?,?,?,?,?,?,?,?,null)",
                    (rid(n), add_days(day_of(NOW), -d), 144, 140, 130, 0, 0, 1, None))
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


def node(env, peer):
    status, _, data = env["api"].handle("GET", f"/v1/nodes/{peer}", {}, b"", "10.0.0.1")
    return status, json.loads(data)


def test_provisional_runner_gets_its_stake_and_attestation(env):
    add_runner(env, 1, "QmOld")
    add_runner(env, 2, "QmNew", age_days=2, ok_days=2)
    set_registry(env, [("QmOld", 1, stake_op(0xa1), "deposited", 10_000, None),
                       ("QmNew", 2, stake_op(0xa2), "deposited", 12_000, None)])
    status, b = node(env, "QmNew")
    assert status == 200, b
    assert set(b) == KEYS
    assert b["peer_id"] == "QmNew"
    assert b["rank"] is None and b["provisional"] is True
    assert b["of"] == 1
    assert b["stake"] == {"status": "deposited", "capacity_ckb": 12_000, "outpoint": stake_op(0xa2)}
    assert b["attestation"] == {"status": "valid", "expiry": EXP // 1000}
    assert set(b["availability"]) == {"d7", "d30", "d365"}
    assert all(isinstance(v, (int, float)) for v in b["availability"].values())
    assert b["check_type"] in ("p2p_verified", "challenge_only")
    assert b["last_check_at"] == NOW - 600


def test_ranked_runner_says_not_provisional(env):
    add_runner(env, 1, "QmOld")
    set_registry(env, [("QmOld", 1, stake_op(0xa1), "deposited", 10_000, None)])
    status, a = node(env, "QmOld")
    assert status == 200, a
    assert set(a) == KEYS
    assert a["rank"] == 1 and a["of"] == 1 and a["provisional"] is False


def test_flagged_runner_gets_200_without_rank(env):
    add_runner(env, 1, "QmOld")
    add_runner(env, 3, "QmFlag", flags=("identity_mismatch",))
    set_registry(env, [("QmOld", 1, stake_op(0xa1), "deposited", 10_000, None),
                       ("QmFlag", 3, stake_op(0xa3), "deposited", 10_000, None)])
    status, f = node(env, "QmFlag")
    assert status == 200, f
    assert f["rank"] is None and f["provisional"] is False and f["of"] == 1
    assert f["stake"]["status"] == "deposited"


def test_registry_row_without_runner(env):
    add_runner(env, 1, "QmOld")
    set_registry(env, [("QmOld", 1, stake_op(0xa1), "deposited", 10_000, None),
                       ("QmRegOnly", 4, stake_op(0xa4), "withdrawn", None, "spent")])
    status, r = node(env, "QmRegOnly")
    assert status == 200, r
    assert set(r) == KEYS
    assert r["peer_id"] == "QmRegOnly"
    assert r["rank"] is None and r["provisional"] is False and r["of"] == 1
    assert r["availability"] == {"d7": None, "d30": None, "d365": None}
    assert r["check_type"] == "none" and r["last_check_at"] == 0
    assert r["stake"] == {"status": "withdrawn", "capacity_ckb": None, "outpoint": stake_op(0xa4)}
    assert r["attestation"] == {"status": "none", "expiry": None}


def test_unknown_peer_is_404(env):
    add_runner(env, 1, "QmOld")
    assert node(env, "QmNobody") == (404, {"error": "unknown_node"})


def test_protocol_doc_describes_unranked_nodes():
    text = open(os.path.join(ROOT, "docs", "PROTOCOL.md"), encoding="utf-8").read()
    assert "unknown_node" in text
    assert "provisional" in text
