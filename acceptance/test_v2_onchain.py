"""v2 Phase 7 acceptance: the monitor's on-chain duties for CSR's registry
(spec/registry.md of ckb-service-runner): config cell clock, registry scan, attestations."""
import copy
import random

import pytest

from csrmon import configcell, csrchain, crypto, molecule, ping, protocol, stat_cell
from csrmon import store as store_mod, config as config_mod
from csrmon.hashing import blake160, from_hex, to_hex
from fakes import cell, block_ts
from fakes_v2 import FakeChainV2
from fakes_stake import FakeChainStake, dao_live, dual_lock
from fakes_v3 import CONFIG_CODE, CONFIG_DEP_TX, CONFIG_LINES, registry_v3_data

MON = (0x51).to_bytes(32, "big")
MON_PK_B = crypto.pubkey_from_secret(MON)
MON_PK = to_hex(MON_PK_B)
CKB = 10 ** 8
SIGHASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
CONFIG_ARGS = "0x" + "a9" * 32
REGISTRY_CODE = "0x" + "47" * 32
NOW = 1_792_281_600


def sk(n):
    return n.to_bytes(32, "big")


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


def monitor_lock(secret=MON):
    return {"code_hash": SIGHASH, "hash_type": "type",
            "args": to_hex(blake160(crypto.pubkey_from_secret(secret)))}


CONFIG_TYPE = {"code_hash": CONFIG_CODE, "hash_type": "data2", "args": CONFIG_ARGS}     # csr-config-type
CONFIG_TYPE_HASH = molecule.script_hash(CONFIG_TYPE)
# Integration (Oct 2026): the registry args are the config_id (= CONFIG_ARGS), as in CSR spec/registry.md §2.
REGISTRY_TYPE = {"code_hash": REGISTRY_CODE, "hash_type": "data2", "args": CONFIG_ARGS}
REGISTRY_TYPE_HASH = molecule.script_hash(REGISTRY_TYPE)


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://monitor-testnet.vericell.net"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"',
             f'config_type_args = "{CONFIG_ARGS}"', f'csr_registry_code_hash = "{REGISTRY_CODE}"',
             f'stat_cell_sighash_dep_tx = "0x{"5d" * 32}"', "clock_update_fee_shannons = 100000",
             *CONFIG_LINES]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    fc = FakeChainStake(tip=12_000_000)
    sent = []

    def on_send(tx):
        sent.append(tx)
        return molecule.tx_hash(tx)

    fc.on_send = on_send
    return {"c": c, "st": st, "fc": fc, "sent": sent}


def add_config_cell(fc, clock_ms, lock=None, pubkey=MON_PK_B, capacity=10_000 * CKB):
    fc.cells.append(cell(dict(CONFIG_TYPE), to_hex(csrchain.config_cell_data(pubkey, clock_ms)),
                         "0x" + "c0" * 32, 0, capacity=capacity, lock=lock or monitor_lock()))


def test_config_type_helpers(env):
    assert configcell.config_type_script(CONFIG_ARGS, CONFIG_CODE) == CONFIG_TYPE
    assert configcell.config_type_hash(CONFIG_ARGS, CONFIG_CODE) == CONFIG_TYPE_HASH
    assert configcell.config_hash_of(env["c"]) == CONFIG_TYPE_HASH
    assert configcell.registry_type_hash(REGISTRY_CODE, "data2", CONFIG_ARGS) == REGISTRY_TYPE_HASH
    assert configcell.registry_hash_of(env["c"]) == REGISTRY_TYPE_HASH


def test_read_clock_and_update(env):
    fc, c = env["fc"], env["c"]
    w = configcell.ConfigCellWriter(env["st"], fc, c, MON)
    assert w.find() is None
    with pytest.raises(configcell.ConfigCellError):
        w.read_clock()
    add_config_cell(fc, clock_ms=block_ts(11_000_000))
    assert w.read_clock() == block_ts(11_000_000)
    h = w.update_clock()
    [tx] = env["sent"]
    assert h == molecule.tx_hash(tx)
    assert [i["previous_output"] for i in tx["inputs"]] == [{"tx_hash": "0x" + "c0" * 32, "index": "0x0"}]
    assert tx["cell_deps"] == [{"out_point": {"tx_hash": "0x" + "5d" * 32, "index": "0x0"},
                                "dep_type": "dep_group"},
                               {"out_point": {"tx_hash": CONFIG_DEP_TX, "index": "0x0"}, "dep_type": "code"}]
    [out] = tx["outputs"]
    assert out["lock"] == monitor_lock() and out["type"] == CONFIG_TYPE
    assert int(out["capacity"], 16) == 10_000 * CKB - 100000
    data = from_hex(tx["outputs_data"][0])
    assert csrchain.parse_config_cell(data) == {"monitor_pubkey": MON_PK, "clock_ms": block_ts(12_000_000)}
    assert len(data) == 49
    placeholder = copy.deepcopy(tx)
    sig = from_hex(tx["witnesses"][0])[20:]
    placeholder["witnesses"][0] = to_hex(molecule.witness_args_bytes(lock=b"\x00" * 65))
    assert crypto.verify(MON_PK_B, stat_cell.sighash_all_digest(placeholder, [0]), sig)


def test_update_skipped_when_clock_not_newer(env):
    fc = env["fc"]
    add_config_cell(fc, clock_ms=block_ts(12_000_000))
    w = configcell.ConfigCellWriter(env["st"], fc, env["c"], MON)
    assert w.update_clock() is None and env["sent"] == []


def test_update_refused_for_foreign_cell(env):
    fc = env["fc"]
    add_config_cell(fc, clock_ms=1, lock=monitor_lock(sk(7)))
    w = configcell.ConfigCellWriter(env["st"], fc, env["c"], MON)
    with pytest.raises(configcell.ConfigCellError):
        w.update_clock()
    fc.cells = []
    add_config_cell(fc, clock_ms=1, pubkey=crypto.pubkey_from_secret(sk(7)))
    with pytest.raises(configcell.ConfigCellError):
        w.update_clock()
    assert env["sent"] == []


# ---------- registry scan ----------

def stake_of(tx_byte):
    return "0x" + f"{0x80 + tx_byte:02x}" * 32 + ":0"


def registry_cell(peer, svc_n, *, signer=MON, network_id=1, att_peer=None, expiry_ms=NOW * 1000 + 7 * 86400000,
                  tx_byte=1):
    data = registry_v3_data(signer, peer=peer, service_pubkey=pk(svc_n), stake=stake_of(tx_byte),
                            expiry_ms=expiry_ms, type_hash=REGISTRY_TYPE_HASH, network_id=network_id,
                            att_peer=att_peer)
    return cell(dict(REGISTRY_TYPE), data, "0x" + f"{tx_byte:02x}" * 32, 0, lock=dual_lock(svc_n))


def test_scan_registry(env):
    fc, st = env["fc"], env["st"]
    fc.cells = [
        registry_cell("QmA", 1, tx_byte=1),
        registry_cell("QmA", 1, expiry_ms=NOW * 1000 + 99, tx_byte=2),     # older attestation
        registry_cell("QmB", 2, signer=sk(9), tx_byte=3),                   # another monitor
        registry_cell("QmC", 3, network_id=0, tx_byte=4),                   # mainnet entry
        registry_cell("QmD", 4, att_peer="QmOther", tx_byte=5),             # attestation for another peer
        cell({"code_hash": REGISTRY_CODE, "hash_type": "data2", "args": CONFIG_ARGS}, "0x0102",
             "0x" + "06" * 32, 0),                                           # not a registry
        registry_cell("QmE", 5, tx_byte=7),
    ]
    for tx_byte, owner in ((1, 1), (2, 1), (3, 2), (4, 3), (5, 4), (7, 5)):
        fc.live[stake_of(tx_byte)] = dao_live(owner, 10_000)
    res = configcell.scan_registry(st, fc, env["c"], MON_PK)
    assert res == {"valid": 3, "invalid": 4, "no_stake": 0}
    assert st.registration_for("QmA") == {"peer_id": "QmA", "service_pubkey": pk(1),
                                          "expiry_ms": NOW * 1000 + 7 * 86400000,
                                          "outpoint": "0x" + "01" * 32 + ":0"}
    assert st.registration_for("QmB") is None and st.registration_for("QmD") is None
    assert st.registration_for("QmE")["service_pubkey"] == pk(5)
    fc.cells = []
    assert configcell.scan_registry(st, fc, env["c"], MON_PK) == {"valid": 0, "invalid": 0, "no_stake": 0}
    assert st.registration_for("QmA") is None


def test_scan_disabled_without_config(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m"', f'db_path = "{tmp_path}/t.db"',
             f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    fc = FakeChainV2()
    fc.fail = True
    assert configcell.scan_registry(store_mod.Store(c.db_path), fc, c, MON_PK) is None


# ---------- attestations ----------

class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


STAKE_OK = "0x" + "5e" * 32 + ":1"


def attest_body(n, peer, network="testnet"):
    p = pk(n)
    return {"peer_id": peer, "service_pubkey": p, "network": network, "stake": STAKE_OK,
            "binding_sig": ping.sign(sk(n), ping.binding_message(peer, p, network))}


def eligible_runner(st, n, peer, ok_probes=1, ts=NOW - 600):
    rid = protocol.runner_id(crypto.pubkey_from_secret(sk(n)))
    st.upsert_runner(rid, service_pubkey=pk(n), peer_id=peer, p2p_pubkey="", reg_outpoint="",
                     mode="inbound", endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=True,
                     now=NOW - 86400 * 3)
    for i in range(ok_probes):
        st.record_probe(rid, ts=ts - i, slot=1000 + i, mode="inbound", result="ok")
    return rid


def test_attest(env):
    fc, st = env["fc"], env["st"]
    add_config_cell(fc, clock_ms=NOW * 1000)
    fc.live[STAKE_OK] = dao_live(1, 10_000)
    w = configcell.ConfigCellWriter(st, fc, env["c"], MON)
    att = configcell.Attester(st, env["c"], MON, w)
    eligible_runner(st, 1, "QmA")
    status, body = att.handle_attest(attest_body(1, "QmA"), "1.1.1.1", NOW)
    assert status == 200
    assert body == csrchain.sign_attestation_v2(MON, peer_id="QmA", service_pubkey=pk(1), network="testnet",
                                                expiry_ms=NOW * 1000 + 7 * 86400000, stake=STAKE_OK,
                                                registry_type_hash=REGISTRY_TYPE_HASH)
    assert csrchain.verify_attestation_v2(body, MON_PK)
    # cached for attest_cache_s: same attestation even if the clock moved
    fc.cells = []
    add_config_cell(fc, clock_ms=NOW * 1000 + 5000)
    assert att.handle_attest(attest_body(1, "QmA"), "1.1.1.1", NOW + 100) == (200, body)
    status, newer = att.handle_attest(attest_body(1, "QmA"), "1.1.1.1", NOW + 3601)
    assert status == 200 and newer["expiry_ms"] == NOW * 1000 + 5000 + 7 * 86400000


def test_attest_refusals(env):
    fc, st = env["fc"], env["st"]
    add_config_cell(fc, clock_ms=NOW * 1000)
    fc.live[STAKE_OK] = dao_live(3, 10_000)
    w = configcell.ConfigCellWriter(st, fc, env["c"], MON)
    att = configcell.Attester(st, env["c"], MON, w)
    assert att.handle_attest({"peer_id": "x"}, "ip", NOW) == (400, {"error": "bad_request"})
    assert att.handle_attest(attest_body(1, "QmA", network="mainnet"), "ip", NOW) == \
        (400, {"error": "wrong_network"})
    bad = attest_body(1, "QmA")
    bad["binding_sig"] = attest_body(2, "QmA")["binding_sig"]
    assert att.handle_attest(bad, "ip", NOW) == (401, {"error": "bad_signature"})
    assert att.handle_attest(attest_body(1, "QmA"), "ip", NOW) == (403, {"error": "not_eligible"})
    eligible_runner(st, 2, "QmB", ok_probes=1, ts=NOW - 90000)      # last ok probe > 24 h ago
    assert att.handle_attest(attest_body(2, "QmB"), "ip", NOW) == (403, {"error": "not_eligible"})
    eligible_runner(st, 3, "QmC")
    assert att.handle_attest(attest_body(3, "QmOtherPeer"), "ip", NOW) == (403, {"error": "not_eligible"})
    fc.fail = True
    assert att.handle_attest(attest_body(3, "QmC"), "ip", NOW) == (503, {"error": "chain_unavailable"})


def test_attest_over_api(env):
    import json
    from csrmon import api as api_mod
    fc, st = env["fc"], env["st"]
    add_config_cell(fc, clock_ms=NOW * 1000)
    fc.live[STAKE_OK] = dao_live(1, 10_000)
    w = configcell.ConfigCellWriter(st, fc, env["c"], MON)
    eligible_runner(st, 1, "QmA")
    a = api_mod.Api(st, env["c"], MON, chain=fc, clock=lambda: NOW,
                    attester=configcell.Attester(st, env["c"], MON, w))
    status, hdrs, data = a.handle("POST", "/v1/attest", {}, json.dumps(attest_body(1, "QmA")).encode(), "1.1.1.1")
    assert status == 200 and json.loads(data)["peer_id"] == "QmA"
    assert hdrs["Access-Control-Allow-Origin"] == "*"
    assert a.handle("GET", "/v1/attest", {}, b"", "1.1.1.1")[0] == 405
    assert a.handle("POST", "/v1/attest", {}, b"{bad", "1.1.1.1")[0] == 400
    none = api_mod.Api(st, env["c"], MON, chain=fc, clock=lambda: NOW)
    status, _, data = none.handle("POST", "/v1/attest", {}, b"{}", "1.1.1.1")
    assert (status, json.loads(data)) == (503, {"error": "unavailable"})
