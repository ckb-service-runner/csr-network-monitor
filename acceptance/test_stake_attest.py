"""Stake phase 2: POST /v1/attest requires a live DAO deposit (field `stake`)."""
import json

import pytest

from csrmon import api as api_mod, configcell, crypto, csrchain, ping, protocol, stat_cell
from csrmon import store as store_mod, config as config_mod
from csrmon.hashing import blake160, to_hex
from fakes import cell
from fakes_stake import DEAD, FakeChainStake, dao_live, sk

MON = (0x51).to_bytes(32, "big")
MON_PK_B = crypto.pubkey_from_secret(MON)
SIGHASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
CONFIG_ARGS = "0x" + "a9" * 32
NOW = 1_792_281_600
S1 = "0x" + "31" * 32 + ":0"
S2 = "0x" + "32" * 32 + ":7"


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
    st.record_probe(rid, ts=NOW - 600, slot=1000, mode="inbound", result="ok")


def body(n, peer, stake=S1):
    p = pk(n)
    b = {"peer_id": peer, "service_pubkey": p, "network": "testnet",
         "binding_sig": ping.sign(sk(n), ping.binding_message(peer, p, "testnet"))}
    if stake is not None:
        b["stake"] = stake
    return b


def test_attest_with_live_deposit(env):
    eligible(env["st"], 1, "QmA")
    env["fc"].live[S1] = dao_live(1, 10_000)
    status, att = env["att"].handle_attest(body(1, "QmA"), "1.1.1.1", NOW)
    assert status == 200
    assert att == csrchain.sign_attestation(MON, peer_id="QmA", service_pubkey=pk(1), network="testnet",
                                            expiry_ms=NOW * 1000 + 7 * 86400000)
    assert env["fc"].live_calls == [S1]
    # the deposit's owner is not known yet at attestation time: any owner is accepted
    eligible(env["st"], 2, "QmB")
    env["fc"].live[S2] = dao_live(9, 20_000)
    assert env["att"].handle_attest(body(2, "QmB", S2), "1.1.1.1", NOW)[0] == 200


def test_stake_required_and_well_formed(env):
    eligible(env["st"], 1, "QmA")
    env["fc"].live[S1] = dao_live(1, 10_000)
    a = env["att"]
    assert a.handle_attest(body(1, "QmA", stake=None), "ip", NOW) == (400, {"error": "bad_request"})
    for bad in ("", "0x12:0", "0x" + "31" * 32, "0x" + "31" * 32 + ":x", 5):
        assert a.handle_attest(body(1, "QmA", stake=bad), "ip", NOW) == (400, {"error": "bad_request"}), bad
    assert env["fc"].live_calls == []


@pytest.mark.parametrize("live,reason", [
    (DEAD, "spent"),
    (None, "not_found"),
    (dao_live(1, 9_999), "too_small"),
    (dao_live(1, 10_000, data="0x" + "01" + "00" * 7), "not_deposit"),
    (dao_live(1, 10_000, type_=None), "not_dao"),
])
def test_stake_invalid(env, live, reason):
    eligible(env["st"], 1, "QmA")
    if live is not None:
        env["fc"].live[S1] = live
    assert env["att"].handle_attest(body(1, "QmA"), "ip", NOW) == \
        (403, {"error": "stake_invalid", "reason": reason})


def test_order_of_checks(env):
    a, fc = env["att"], env["fc"]
    # not eligible is reported before the stake is looked up
    assert a.handle_attest(body(1, "QmA"), "ip", NOW) == (403, {"error": "not_eligible"})
    assert fc.live_calls == []
    eligible(env["st"], 1, "QmA")
    fc.live[S1] = dao_live(1, 10_000)
    fc.fail = True
    assert a.handle_attest(body(1, "QmA"), "ip", NOW) == (503, {"error": "chain_unavailable"})


def test_stake_in_use_by_another_registration(env):
    st, fc, a = env["st"], env["fc"], env["att"]
    eligible(st, 1, "QmA")
    eligible(st, 2, "QmB")
    fc.live[S1] = dao_live(1, 10_000)
    st.set_stakes([{"peer_id": "QmA", "service_pubkey": pk(1), "reg_outpoint": "0x" + "01" * 32 + ":0",
                    "expiry_ms": NOW * 1000, "stake_outpoint": S1, "status": "deposited", "capacity_ckb": 10_000,
                    "reason": None}])
    assert a.handle_attest(body(2, "QmB"), "ip", NOW) == (403, {"error": "stake_in_use"})
    assert a.handle_attest(body(1, "QmA"), "ip", NOW)[0] == 200          # its own registration: fine
    up = S1.upper().replace("0X", "0x")
    assert a.handle_attest(body(2, "QmB", up), "ip", NOW) == (403, {"error": "stake_in_use"})


def test_cached_attestation_still_checks_the_stake(env):
    st, fc, a = env["st"], env["fc"], env["att"]
    eligible(st, 1, "QmA")
    fc.live[S1] = dao_live(1, 10_000)
    status, first = a.handle_attest(body(1, "QmA"), "ip", NOW)
    assert status == 200
    assert a.handle_attest(body(1, "QmA"), "ip", NOW + 10) == (200, first)
    fc.live[S1] = DEAD
    assert a.handle_attest(body(1, "QmA"), "ip", NOW + 20) == (403, {"error": "stake_invalid", "reason": "spent"})


def test_over_http_api(env):
    eligible(env["st"], 1, "QmA")
    env["fc"].live[S1] = dao_live(1, 10_000)
    api = api_mod.Api(env["st"], env["c"], MON, chain=env["fc"], clock=lambda: NOW, attester=env["att"])
    status, _, data = api.handle("POST", "/v1/attest", {}, json.dumps(body(1, "QmA")).encode(), "1.1.1.1")
    assert status == 200 and json.loads(data)["peer_id"] == "QmA"
    status, _, data = api.handle("POST", "/v1/attest", {}, json.dumps(body(1, "QmA", stake=None)).encode(),
                                 "1.1.1.1")
    assert (status, json.loads(data)) == (400, {"error": "bad_request"})
    env["fc"].live[S1] = DEAD
    status, _, data = api.handle("POST", "/v1/attest", {}, json.dumps(body(1, "QmA")).encode(), "1.1.1.1")
    assert (status, json.loads(data)) == (403, {"error": "stake_invalid", "reason": "spent"})
