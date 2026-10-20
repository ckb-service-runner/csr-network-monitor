"""Stake phase 2: registry scan with DAO stakes, store, /v1/nodes stake object, docs."""
import json
import os

import pytest

from csrmon import api as api_mod, configcell, crypto, csrchain, molecule, protocol, stat_cell
from csrmon import store as store_mod, config as config_mod
from csrmon.hashing import to_hex
from fakes import cell
from fakes_stake import DEAD, FakeChainStake, dao_live, dual_lock, secp_lock, sk

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MON = (0x51).to_bytes(32, "big")
MON_PK = to_hex(crypto.pubkey_from_secret(MON))
CONFIG_ARGS = "0x" + "a9" * 32
REGISTRY_CODE = "0x" + "47" * 32
NOW = 1_792_281_600
EXP = NOW * 1000 + 7 * 86400000


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


def stake_op(b, i=0):
    return "0x" + f"{b:02x}" * 32 + f":{i}"


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"',
             f'config_type_args = "{CONFIG_ARGS}"', f'csr_registry_code_hash = "{REGISTRY_CODE}"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    return {"c": c, "st": store_mod.Store(c.db_path), "fc": FakeChainStake(tip=12_000_000)}


def reg_cell(peer, n, stake, *, owner=None, tx_byte=1, block=10, tx_index=0, expiry_ms=EXP, lock=None):
    att = csrchain.sign_attestation(MON, peer_id=peer, service_pubkey=pk(n), network="testnet", expiry_ms=expiry_ms)
    reg = {"peer_id": peer, "service_pubkey": pk(n), "payout_lock_hash": "0x" + "77" * 32, "network": 1,
           "attestation": {k: att[k] for k in ("peer_id", "service_pubkey", "network_id", "expiry_ms", "signature")},
           "prekeys": "0x", "stake": stake}
    t = {"code_hash": REGISTRY_CODE, "hash_type": "data2", "args": configcell.config_type_hash(CONFIG_ARGS)}
    c = cell(t, to_hex(csrchain.encode_registry(reg)), "0x" + f"{tx_byte:02x}" * 32, 0,
             lock=lock or dual_lock(owner if owner is not None else n), block=block)
    c["tx_index"] = hex(tx_index)
    return c


def scan(env):
    return configcell.scan_registry(env["st"], env["fc"], env["c"], MON_PK)


def test_stake_states(env):
    fc, st = env["fc"], env["st"]
    fc.cells = [
        reg_cell("QmOk", 1, stake_op(0xa1), tx_byte=1),
        reg_cell("QmGone", 2, stake_op(0xa2), tx_byte=2),
        reg_cell("QmSmall", 3, stake_op(0xa3), tx_byte=3),
        reg_cell("QmForeign", 4, stake_op(0xa4), tx_byte=4),
        reg_cell("QmMissing", 5, stake_op(0xa5), tx_byte=5),
        reg_cell("QmPhase1", 6, stake_op(0xa6), tx_byte=6),
    ]
    fc.live[stake_op(0xa1)] = dao_live(1, 10_000)
    fc.live[stake_op(0xa2)] = DEAD
    fc.live[stake_op(0xa3)] = dao_live(3, 9_999)
    fc.live[stake_op(0xa4)] = dao_live(9, 50_000)               # deposit of another owner (A8: allowed, the contract checked its consent)
    fc.live[stake_op(0xa6)] = dao_live(6, 10_000, data="0x" + "2a" + "00" * 7)
    assert scan(env) == {"valid": 2, "invalid": 0, "no_stake": 4}
    assert st.registration_for("QmOk") == {"peer_id": "QmOk", "service_pubkey": pk(1), "expiry_ms": EXP,
                                           "outpoint": "0x" + "01" * 32 + ":0"}
    for peer in ("QmGone", "QmSmall", "QmMissing", "QmPhase1"):
        assert st.registration_for(peer) is None, peer
    want = {"QmOk": ("deposited", 10_000, None), "QmGone": ("withdrawn", None, "spent"),
            "QmSmall": ("invalid", 9_999, "too_small"), "QmForeign": ("deposited", 50_000, None),
            "QmMissing": ("invalid", None, "not_found"), "QmPhase1": ("invalid", 10_000, "not_deposit")}
    for peer, (status, cap, reason) in want.items():
        r = st.stake_for(peer)
        assert (r["status"], r["capacity_ckb"], r["reason"]) == (status, cap, reason), peer
    assert st.stake_for("QmOk")["stake_outpoint"] == stake_op(0xa1)
    assert st.stake_for("QmOk")["reg_outpoint"] == "0x" + "01" * 32 + ":0"
    assert st.stake_for("QmNobody") is None
    # the deposit is withdrawn later: the registration stops counting at the next scan
    fc.live[stake_op(0xa1)] = DEAD
    assert scan(env) == {"valid": 1, "invalid": 0, "no_stake": 5}
    assert st.registration_for("QmOk") is None
    assert st.stake_for("QmOk")["status"] == "withdrawn"
    assert st.registration_for("QmForeign")["service_pubkey"] == pk(4)


def test_one_deposit_one_registration(env):
    fc, st = env["fc"], env["st"]
    s = stake_op(0xb0, 2)
    fc.cells = [
        reg_cell("QmLate", 2, s, owner=1, tx_byte=3, block=20, tx_index=0),
        reg_cell("QmSameBlockLater", 3, s, owner=1, tx_byte=2, block=10, tx_index=5),
        reg_cell("QmFirst", 1, s, owner=1, tx_byte=1, block=10, tx_index=1),
    ]
    fc.live[s] = dao_live(1, 10_000)
    assert scan(env) == {"valid": 1, "invalid": 0, "no_stake": 2}
    assert st.registration_for("QmFirst") is not None
    assert st.registration_for("QmLate") is None and st.registration_for("QmSameBlockLater") is None
    assert (st.stake_for("QmLate")["status"], st.stake_for("QmLate")["reason"]) == ("duplicate", "stake_in_use")
    assert st.stake_for("QmSameBlockLater")["status"] == "duplicate"
    assert st.stake_user(s) == "QmFirst"
    assert st.stake_user(stake_op(0xb1)) is None


def test_duplicate_does_not_block_a_valid_later_registration_of_another_deposit(env):
    fc, st = env["fc"], env["st"]
    fc.cells = [reg_cell("QmA", 1, stake_op(0xc1), tx_byte=1, block=5),
                reg_cell("QmA", 1, stake_op(0xc2), tx_byte=2, block=6, expiry_ms=EXP - 1)]
    fc.live[stake_op(0xc1)] = DEAD
    fc.live[stake_op(0xc2)] = dao_live(1, 10_000)
    assert scan(env) == {"valid": 1, "invalid": 0, "no_stake": 1}
    # stake_for prefers the deposited row although its attestation is older
    assert st.stake_for("QmA")["stake_outpoint"] == stake_op(0xc2)
    assert st.registration_for("QmA")["outpoint"] == "0x" + "02" * 32 + ":0"


def test_invalid_cells(env):
    fc = env["fc"]
    bad_lock = {"code_hash": "0x" + "e8" * 32, "hash_type": "data2", "args": "0x" + "11" * 32}
    fc.cells = [reg_cell("QmShortLock", 1, stake_op(0xd1), tx_byte=1, lock=bad_lock),
                reg_cell("QmOk", 2, stake_op(0xd2), tx_byte=2)]
    # a v1 (6-field) registry cell is invalid
    v1 = dict(reg_cell("QmV1", 3, stake_op(0xd3), tx_byte=3))
    import csr_vectors as V
    v1["output_data"] = V.REGISTRY_DATA
    fc.cells.append(v1)
    fc.live[stake_op(0xd1)] = dao_live(1, 10_000)
    fc.live[stake_op(0xd2)] = dao_live(2, 10_000)
    assert scan(env) == {"valid": 1, "invalid": 2, "no_stake": 0}
    assert env["st"].stake_for("QmShortLock") is None


def test_min_stake_from_config(env, tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/u.db"', f'key_path = "{tmp_path}/k.key"',
             f'config_type_args = "{CONFIG_ARGS}"', f'csr_registry_code_hash = "{REGISTRY_CODE}"',
             "min_stake_ckb = 500"]
    (tmp_path / "u.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "u.toml"))
    fc = FakeChainStake()
    fc.cells = [reg_cell("QmA", 1, stake_op(0xe1))]
    fc.live[stake_op(0xe1)] = dao_live(1, 600)
    st = store_mod.Store(c.db_path)
    assert configcell.scan_registry(st, fc, c, MON_PK) == {"valid": 1, "invalid": 0, "no_stake": 0}


def test_scan_rpc_failure_keeps_previous_state(env):
    fc, st = env["fc"], env["st"]
    fc.cells = [reg_cell("QmOk", 1, stake_op(0xf1))]
    fc.live[stake_op(0xf1)] = dao_live(1, 10_000)
    scan(env)
    fc.fail = True
    with pytest.raises(Exception):
        scan(env)
    assert st.registration_for("QmOk") is not None and st.stake_for("QmOk")["status"] == "deposited"


# ---------- /v1/nodes ----------

def ranked_runner(st, n, peer):
    import sqlite3
    from csrmon.store import add_days, day_of
    rid = protocol.runner_id(crypto.pubkey_from_secret(sk(n)))
    st.upsert_runner(rid, service_pubkey=pk(n), peer_id=peer, p2p_pubkey="", reg_outpoint="", mode="inbound",
                     endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=True, now=NOW - 40 * 86400)
    st.record_probe(rid, ts=NOW - 600, slot=n * 1000, mode="inbound", result="ok", lag=1, in_sync=True,
                    country="DE", asn=3320)
    con = sqlite3.connect(st_path(st))
    for d in range(30):
        con.execute("insert or replace into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                    " p2p_total, p2p_ok, median_lag, median_peers, score) values (?,?,?,?,?,?,?,?,?,null)",
                    (rid, add_days(day_of(NOW), -d), 144, 140, 130, 0, 0, 1, None))
    con.commit()
    con.close()


def st_path(st):
    return st._con.execute("pragma database_list").fetchone()[2]


def test_nodes_stake_object(env):
    fc, st, c = env["fc"], env["st"], env["c"]
    st.set_meta("monitor_start", str(NOW - 60 * 86400))
    ranked_runner(st, 1, "QmA")
    ranked_runner(st, 2, "QmB")
    ranked_runner(st, 3, "QmC")
    fc.cells = [reg_cell("QmA", 1, stake_op(0x71), tx_byte=1), reg_cell("QmB", 2, stake_op(0x72), tx_byte=2)]
    fc.live[stake_op(0x71)] = dao_live(1, 12_000)
    fc.live[stake_op(0x72)] = DEAD
    scan(env)
    api = api_mod.Api(st, c, MON, clock=lambda: NOW)

    def node(peer):
        status, _, data = api.handle("GET", f"/v1/nodes/{peer}", {}, b"", "10.0.0.1")
        assert status == 200, data
        return json.loads(data)

    a, b, cc = node("QmA"), node("QmB"), node("QmC")
    assert a["stake"] == {"status": "deposited", "capacity_ckb": 12_000, "outpoint": stake_op(0x71)}
    assert a["attestation"] == {"status": "valid", "expiry": EXP // 1000}
    assert b["stake"] == {"status": "withdrawn", "capacity_ckb": None, "outpoint": stake_op(0x72)}
    assert b["attestation"] == {"status": "none", "expiry": None}       # registration does not count
    assert cc["stake"] == {"status": "none", "capacity_ckb": None, "outpoint": None}


def test_docs():
    proto = open(os.path.join(ROOT, "docs", "PROTOCOL.md"), encoding="utf-8").read()
    for s in ("stake", "stake_invalid", "stake_in_use", "min_stake_ckb", "duplicate", "withdrawn",
              "payout_lock_hash", "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e"):
        assert s in proto, s
    assert "float_lock_hash" not in proto
    for f in ("config/monitor-testnet.toml", "config/monitor-mainnet.toml"):
        assert "min_stake_ckb" in open(os.path.join(ROOT, f), encoding="utf-8").read(), f
    dec = open(os.path.join(ROOT, "DECISIONS.md"), encoding="utf-8").read()
    assert "D-A7-1" in dec
