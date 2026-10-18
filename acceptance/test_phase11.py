"""Phase 11 acceptance: Molecule encoding, CKB transactions, the weekly stat cell.

Vectors for the transaction below were produced with an independent CKB library.
"""
import copy

import pytest

from csrmon import molecule, stat_cell, epochs, crypto, store as store_mod, config as config_mod
from csrmon.hashing import ckb_blake2b, blake160, from_hex, to_hex
from fakes import FakeChain, cell

TX = {
    "version": "0x0",
    "cell_deps": [
        {"out_point": {"tx_hash": "0x" + "a1" * 32, "index": "0x0"}, "dep_type": "dep_group"},
        {"out_point": {"tx_hash": "0x" + "b2" * 32, "index": "0x3"}, "dep_type": "code"}],
    "header_deps": ["0x" + "c3" * 32],
    "inputs": [
        {"since": "0x0", "previous_output": {"tx_hash": "0x" + "d4" * 32, "index": "0x1"}},
        {"since": "0x2000000000000005", "previous_output": {"tx_hash": "0x" + "e5" * 32, "index": "0x0"}}],
    "outputs": [
        {"capacity": "0x9502f9000",
         "lock": {"code_hash": "0x" + "11" * 32, "hash_type": "type", "args": "0x" + "22" * 20},
         "type": {"code_hash": "0x00000000000000000000000000000000000000000000000000545950455f4944",
                  "hash_type": "type", "args": "0x" + "33" * 32}},
        {"capacity": "0x174876e800",
         "lock": {"code_hash": "0x" + "44" * 32, "hash_type": "data1", "args": "0x"}, "type": None}],
    "outputs_data": ["0x0102030405", "0x"],
    "witnesses": ["0x55000000100000005500000055000000" + "41000000" + "00" * 65, "0x", "0xabcdef"],
}


def test_script_encoding_and_hash():
    lock = TX["outputs"][0]["lock"]
    assert molecule.script_bytes(lock).hex() == (
        "49000000100000003000000031000000" + "11" * 32 + "01" + "14000000" + "22" * 20)
    assert molecule.script_hash(lock) == \
        "0x94bfe0b549decec8d74c54769b74bf53100d936d70b6557631ba2deea49a8942"
    empty = {"code_hash": "0x" + "00" * 32, "hash_type": "data", "args": "0x"}
    assert molecule.script_bytes(empty).hex() == \
        "35000000100000003000000031000000" + "00" * 32 + "00" + "00000000"
    assert molecule.HASH_TYPES == {"data": 0, "type": 1, "data1": 2, "data2": 4}


def test_struct_encodings():
    op = {"tx_hash": "0x" + "d4" * 32, "index": "0x1"}
    assert molecule.out_point_bytes(op) == bytes.fromhex("d4" * 32) + (1).to_bytes(4, "little")
    ci = molecule.cell_input_bytes(TX["inputs"][1])
    assert len(ci) == 44 and ci[:8] == (0x2000000000000005).to_bytes(8, "little")
    dep = molecule.cell_dep_bytes(TX["cell_deps"][0])
    assert len(dep) == 37 and dep[-1] == 1
    assert molecule.cell_dep_bytes(TX["cell_deps"][1])[-1] == 0


def test_cell_output_encoding():
    assert molecule.cell_output_bytes(TX["outputs"][0]).hex() == (
        "b600000010000000180000006100000000902f5009000000490000001000000030000000310000001111111111"
        "111111111111111111111111111111111111111111111111111111011400000022222222222222222222222222"
        "222222222222225500000010000000300000003100000000000000000000000000000000000000000000000000"
        "000000545950455f494401200000003333333333333333333333333333333333333333333333333333333333333333")
    assert molecule.cell_output_bytes(TX["outputs"][1]).hex() == (
        "4d00000010000000180000004d00000000e87648170000003500000010000000300000003100000044444444444"
        "444444444444444444444444444444444444444444444444444440200000000")


def test_witness_args():
    assert molecule.witness_args_bytes(lock=b"\x00" * 65).hex() == \
        "55000000100000005500000055000000" + "41000000" + "00" * 65
    assert molecule.witness_args_bytes().hex() == "10000000100000001000000010000000"


def test_transaction_hash_and_size():
    assert molecule.tx_hash(TX) == "0xcba7927e655ad494a2833e8240dc640068f0b8ca7319f67169b51f048d8fd464"
    assert molecule.tx_hash(TX) == to_hex(ckb_blake2b(molecule.raw_transaction_bytes(TX)))
    assert len(molecule.transaction_bytes(TX)) == 662
    empty = {"version": "0x0", "cell_deps": [], "header_deps": [], "inputs": [], "outputs": [],
             "outputs_data": [], "witnesses": []}
    raw = molecule.raw_transaction_bytes(empty)
    assert raw.hex() == ("34000000" "1c000000" "20000000" "24000000" "28000000" "2c000000" "30000000"
                         "00000000" "00000000" "00000000" "00000000" "04000000" "04000000")


def test_sighash_and_type_id():
    assert stat_cell.sighash_all_digest(TX, [0, 1]) == bytes.fromhex(
        "4bd9e2baa782a390e9b71b0c13ad537266d14bedd7a99750a5cd6ace8b918531")
    assert stat_cell.type_id_args(TX["inputs"][0], 0) == \
        "0x70e1f01ff0e3c91e4599e5a1c09ff0c149346f3add3a6bc066d56812b6c81f0e"
    assert stat_cell.TYPE_ID_CODE_HASH == \
        "0x00000000000000000000000000000000000000000000000000545950455f4944"


def test_sign_input_group():
    secret = (77).to_bytes(32, "big")
    tx = copy.deepcopy(TX)
    tx["witnesses"][0] = "0x"
    signed = stat_cell.sign_input_group(tx, secret, [0, 1])
    w = from_hex(signed["witnesses"][0])
    assert w[:20] == bytes.fromhex("55000000100000005500000055000000" "41000000")
    sig = w[20:]
    placeholder = copy.deepcopy(signed)
    placeholder["witnesses"][0] = to_hex(molecule.witness_args_bytes(lock=b"\x00" * 65))
    digest = stat_cell.sighash_all_digest(placeholder, [0, 1])
    assert crypto.verify(crypto.pubkey_from_secret(secret), digest, sig)
    assert tx["witnesses"][0] == "0x"           # input not modified


def test_occupied_capacity():
    out = TX["outputs"][0]
    assert stat_cell.occupied_capacity(out, b"\x01\x02\x03\x04\x05") == (8 + 53 + 65 + 5) * 10**8
    assert stat_cell.occupied_capacity(TX["outputs"][1], b"") == (8 + 33) * 10**8


# ---------- stat cell writer ----------

MON = (11).to_bytes(32, "big")
CKB = 10**8
ACP = "0x" + "ac" * 32
SIGHASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"',
             "stat_cell_enabled = true", f'stat_cell_acp_code_hash = "{ACP}"',
             f'stat_cell_acp_dep_tx = "0x{"de" * 32}"', f'stat_cell_sighash_dep_tx = "0x{"5d" * 32}"',
             "stat_cell_capacity_ckb = 400", "stat_cell_fee_shannons = 100000"]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    cfg = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(cfg.db_path)
    start = 1_791_763_200 - 3 * epochs.EPOCH_SECONDS     # a Monday, three weeks earlier
    st.set_meta("monitor_start", str(start))
    fc = FakeChain(tip=12_000_000)
    epochs.build_pending(st, fc, MON, cfg, now=start + 2 * epochs.EPOCH_SECONDS + 10)
    assert [e["epoch"] for e in st.list_epochs()] == [1, 2]
    args = to_hex(blake160(crypto.pubkey_from_secret(MON)))
    funding = {"code_hash": SIGHASH, "hash_type": "type", "args": args}
    fc.cells = [
        cell(None, "0x", "0x" + "f1" * 32, 0, capacity=300 * CKB, lock=funding),
        cell(None, "0x01", "0x" + "f2" * 32, 0, capacity=5000 * CKB, lock=funding),   # has data
        cell({"code_hash": "0x" + "77" * 32, "hash_type": "type", "args": "0x"}, "0x",
             "0x" + "f3" * 32, 0, capacity=5000 * CKB, lock=funding),                # has type
        cell(None, "0x", "0x" + "f4" * 32, 1, capacity=300 * CKB, lock=funding),
    ]
    caps = {}

    def on_send(tx):
        h = molecule.tx_hash(tx)
        spent = {(i["previous_output"]["tx_hash"], i["previous_output"]["index"]) for i in tx["inputs"]}
        for c in fc.cells:
            key = (c["out_point"]["tx_hash"], c["out_point"]["index"])
            caps[key] = int(c["output"]["capacity"], 16)
        fc.cells = [c for c in fc.cells
                    if (c["out_point"]["tx_hash"], c["out_point"]["index"]) not in spent]
        for idx, out in enumerate(tx["outputs"]):
            fc.cells.append({"output": copy.deepcopy(out), "output_data": tx["outputs_data"][idx],
                             "out_point": {"tx_hash": h, "index": hex(idx)},
                             "block_number": "0x10", "tx_index": "0x0"})
        return h

    fc.on_send = on_send
    return {"cfg": cfg, "st": st, "chain": fc, "funding": funding, "args": args, "caps": caps}


def input_capacity(env, tx):
    return sum(env["caps"][(i["previous_output"]["tx_hash"], i["previous_output"]["index"])]
               for i in tx["inputs"])


def out_capacity(tx):
    return sum(int(o["capacity"], 16) for o in tx["outputs"])


def check_signature(tx, group):
    placeholder = copy.deepcopy(tx)
    sig = from_hex(tx["witnesses"][group[0]])[20:]
    placeholder["witnesses"][group[0]] = to_hex(molecule.witness_args_bytes(lock=b"\x00" * 65))
    digest = stat_cell.sighash_all_digest(placeholder, group)
    return crypto.verify(crypto.pubkey_from_secret(MON), digest, sig)


def test_writer_scripts(env):
    w = stat_cell.StatCellWriter(env["st"], env["chain"], env["cfg"], MON)
    assert w.lock_script() == {"code_hash": ACP, "hash_type": "type", "args": env["args"]}
    assert w.funding_lock() == env["funding"]
    assert w.find_stat_cell() is None


def test_create_then_update(env):
    st, fc = env["st"], env["chain"]
    w = stat_cell.StatCellWriter(st, fc, env["cfg"], MON)
    h1 = w.publish(1)
    [tx] = fc.sent
    assert h1 == molecule.tx_hash(tx) and st.get_epoch(1)["stat_cell_tx"] == h1
    ins = [(i["previous_output"]["tx_hash"], i["previous_output"]["index"]) for i in tx["inputs"]]
    assert ins == [("0x" + "f1" * 32, "0x0"), ("0x" + "f4" * 32, "0x1")]
    assert tx["cell_deps"] == [{"out_point": {"tx_hash": "0x" + "5d" * 32, "index": "0x0"},
                                "dep_type": "dep_group"}]
    out0 = tx["outputs"][0]
    assert out0["lock"] == w.lock_script()
    assert out0["type"] == {"code_hash": stat_cell.TYPE_ID_CODE_HASH, "hash_type": "type",
                            "args": stat_cell.type_id_args(tx["inputs"][0], 0)}
    assert int(out0["capacity"], 16) == 400 * CKB
    assert tx["outputs_data"][0] == st.get_epoch(1)["data_hex"]
    assert tx["outputs"][1]["lock"] == env["funding"] and tx["outputs"][1]["type"] is None
    assert tx["outputs_data"][1] == "0x"
    assert input_capacity(env, tx) - out_capacity(tx) == 100000
    assert len(tx["witnesses"]) == 2 and tx["witnesses"][1] == "0x"
    assert check_signature(tx, [0, 1])
    assert st.get_meta("stat_cell_type_hash") == molecule.script_hash(out0["type"])
    found = w.find_stat_cell()
    assert found["out_point"] == {"tx_hash": h1, "index": "0x0"}

    assert w.publish(1) == h1 and len(fc.sent) == 1          # idempotent

    h2 = w.publish(2)
    tx2 = fc.sent[-1]
    assert [i["previous_output"] for i in tx2["inputs"]] == [{"tx_hash": h1, "index": "0x0"}]
    assert tx2["cell_deps"] == [{"out_point": {"tx_hash": "0x" + "de" * 32, "index": "0x0"},
                                 "dep_type": "dep_group"}]
    assert len(tx2["outputs"]) == 1
    assert tx2["outputs"][0]["type"] == out0["type"] and tx2["outputs"][0]["lock"] == out0["lock"]
    assert int(tx2["outputs"][0]["capacity"], 16) == 400 * CKB - 100000
    assert tx2["outputs_data"][0] == st.get_epoch(2)["data_hex"]
    assert check_signature(tx2, [0])
    assert st.get_epoch(2)["stat_cell_tx"] == h2


def test_small_change_goes_to_stat_cell(env):
    fc = env["chain"]
    fc.cells = [cell(None, "0x", "0x" + "f9" * 32, 0, capacity=440 * CKB, lock=env["funding"])]
    w = stat_cell.StatCellWriter(env["st"], fc, env["cfg"], MON)
    w.publish(1)
    tx = fc.sent[-1]
    assert len(tx["outputs"]) == 1
    assert int(tx["outputs"][0]["capacity"], 16) == 440 * CKB - 100000


def test_insufficient_funds_and_capacity(env):
    fc = env["chain"]
    fc.cells = [cell(None, "0x", "0x" + "f9" * 32, 0, capacity=200 * CKB, lock=env["funding"])]
    w = stat_cell.StatCellWriter(env["st"], fc, env["cfg"], MON)
    with pytest.raises(stat_cell.InsufficientFunds):
        w.publish(1)
    assert fc.sent == [] and env["st"].get_epoch(1)["stat_cell_tx"] is None
    # an existing stat cell that cannot pay the fee any more
    tight = cell({"code_hash": stat_cell.TYPE_ID_CODE_HASH, "hash_type": "type", "args": "0x" + "12" * 32},
                 env["st"].get_epoch(1)["data_hex"], "0x" + "fa" * 32, 0,
                 capacity=285 * CKB, lock=w.lock_script())
    fc.cells = [tight]
    env["st"].set_meta("stat_cell_type_args", "0x" + "12" * 32)
    with pytest.raises(stat_cell.InsufficientCapacity):
        w.publish(2)
