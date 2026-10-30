"""fix-monitor-stake-ranking, phase 3: POST /v1/attest only accepts the registry's own stake once a
registry cell exists (F-CON-002)."""
import os

import pytest

from csrmon import configcell, crypto, csrchain, ping, protocol, stat_cell
from csrmon import store as store_mod, config as config_mod
from csrmon.hashing import blake160, to_hex
from fakes import cell
from fakes_stake import DEAD, FakeChainStake, dao_live, sk

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MON = (0x51).to_bytes(32, "big")
MON_PK_B = crypto.pubkey_from_secret(MON)
SIGHASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
CONFIG_ARGS = "0x" + "a9" * 32
NOW = 1_792_281_600
S1 = "0x" + "31" * 32 + ":0"
S2 = "0x" + "32" * 32 + ":7"
MISMATCH = (403, {"error": "stake_mismatch"})


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"',
             f'config_type_args = "{CONFIG_ARGS}"', f'csr_registry_code_hash = "0x{"47" * 32}"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    fc = FakeChainStake(tip=12_000_000)
    ctype = {"code_hash": stat_cell.TYPE_ID_CODE_HASH, "hash_type": "type", "args": CONFIG_ARGS}
    fc.cells.append(cell(ctype, to_hex(csrchain.config_cell_data(MON_PK_B, NOW * 1000)), "0x" + "c0" * 32, 0,
                         lock={"code_hash": SIGHASH, "hash_type": "type", "args": to_hex(blake160(MON_PK_B))}))
    w = configcell.ConfigCellWriter(st, fc, c, MON)
    return {"c": c, "st": st, "fc": fc, "att": configcell.Attester(st, c, MON, w)}


def eligible(st, n, peer):
    rid = protocol.runner_id(crypto.pubkey_from_secret(sk(n)))
    st.upsert_runner(rid, service_pubkey=pk(n), peer_id=peer, p2p_pubkey="", reg_outpoint="", mode="inbound",
                     endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=True, now=NOW - 3 * 86400)
    st.record_probe(rid, ts=NOW - 600, slot=1000 + n, mode="inbound", result="ok")


def body(n, peer, stake):
    p = pk(n)
    return {"peer_id": peer, "service_pubkey": p, "network": "testnet", "stake": stake,
            "binding_sig": ping.sign(sk(n), ping.binding_message(peer, p, "testnet"))}


def registry(st, rows):
    """rows: (peer, key n, stake out point, status) as written by the registry scan."""
    st.set_stakes([{"peer_id": p, "service_pubkey": pk(n), "reg_outpoint": "0x" + f"{i + 1:02x}" * 32 + ":0",
                    "expiry_ms": NOW * 1000, "stake_outpoint": s, "status": status,
                    "capacity_ckb": 10_000 if status == "deposited" else None,
                    "reason": None if status == "deposited" else "spent"}
                   for i, (p, n, s, status) in enumerate(rows)])


def test_registered_peer_must_name_its_registry_stake(env):
    st, fc, a = env["st"], env["fc"], env["att"]
    eligible(st, 1, "QmA")
    fc.live[S1] = dao_live(1, 10_000)
    fc.live[S2] = dao_live(9, 20_000)                 # a stranger's unused deposit
    registry(st, [("QmA", 1, S1, "deposited")])
    assert a.handle_attest(body(1, "QmA", S2), "ip", NOW) == MISMATCH
    status, att = a.handle_attest(body(1, "QmA", S1), "ip", NOW)
    assert status == 200
    assert att == csrchain.sign_attestation(MON, peer_id="QmA", service_pubkey=pk(1), network="testnet",
                                            expiry_ms=NOW * 1000 + 7 * 86400000)
    up = S1.upper().replace("0X", "0x")               # same out point, other spelling
    assert a.handle_attest(body(1, "QmA", up), "ip", NOW + 5)[0] == 200


def test_withdrawn_registry_stake_cannot_be_swapped_for_another_deposit(env):
    st, fc, a = env["st"], env["fc"], env["att"]
    eligible(st, 1, "QmA")
    fc.live[S1] = DEAD
    fc.live[S2] = dao_live(9, 20_000)
    registry(st, [("QmA", 1, S1, "withdrawn")])
    assert a.handle_attest(body(1, "QmA", S2), "ip", NOW) == MISMATCH
    assert a.handle_attest(body(1, "QmA", S1), "ip", NOW)[0] == 403


def test_service_key_registered_under_another_peer(env):
    st, fc, a = env["st"], env["fc"], env["att"]
    eligible(st, 1, "QmNew")
    fc.live[S2] = dao_live(9, 20_000)
    registry(st, [("QmOld", 1, S1, "deposited")])
    assert a.handle_attest(body(1, "QmNew", S2), "ip", NOW) == MISMATCH


def test_unregistered_peer_keeps_the_old_rules(env):
    st, fc, a = env["st"], env["fc"], env["att"]
    eligible(st, 2, "QmB")
    fc.live[S1] = dao_live(1, 10_000)
    fc.live[S2] = dao_live(9, 20_000)
    registry(st, [("QmA", 1, S1, "deposited")])
    assert a.handle_attest(body(2, "QmB", S2), "ip", NOW)[0] == 200
    assert a.handle_attest(body(2, "QmB", S1), "ip", NOW) == (403, {"error": "stake_in_use"})


def test_cached_attestation_does_not_bypass_the_check(env):
    st, fc, a = env["st"], env["fc"], env["att"]
    eligible(st, 1, "QmA")
    fc.live[S1] = dao_live(1, 10_000)
    fc.live[S2] = dao_live(9, 20_000)
    registry(st, [("QmA", 1, S1, "deposited")])
    assert a.handle_attest(body(1, "QmA", S1), "ip", NOW)[0] == 200
    fc.live[S1] = DEAD
    registry(st, [("QmA", 1, S1, "withdrawn")])
    assert a.handle_attest(body(1, "QmA", S2), "ip", NOW + 10) == MISMATCH


def test_protocol_doc_lists_stake_mismatch():
    text = open(os.path.join(ROOT, "docs", "PROTOCOL.md"), encoding="utf-8").read()
    assert "stake_mismatch" in text
