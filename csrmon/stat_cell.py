"""Stat cell transactions: Type ID, sighash signing, create / update."""
import copy

from . import crypto
from .hashing import blake160, ckb_blake2b, from_hex, to_hex
from .molecule import (cell_input_bytes, script_hash, tx_hash, witness_args_bytes)

TYPE_ID_CODE_HASH = "0x00000000000000000000000000000000000000000000000000545950455f4944"
CKB = 10**8
MIN_CHANGE = 61 * CKB


RESEND_AFTER_BLOCKS = 100


def next_action(status, *, sent_block, tip) -> str:
    """What to do with a sent stat cell transaction: published, wait or resend."""
    if status == "committed":
        return "published"
    if status in ("pending", "proposed"):
        return "wait"
    if status == "rejected":
        return "resend"
    if sent_block is None or tip >= sent_block + RESEND_AFTER_BLOCKS:
        return "resend"
    return "wait"


class InsufficientFunds(Exception):
    pass


class InsufficientCapacity(Exception):
    pass


def type_id_args(first_input, output_index) -> str:
    return to_hex(ckb_blake2b(cell_input_bytes(first_input) + int(output_index).to_bytes(8, "little")))


def sighash_all_digest(tx, group) -> bytes:
    witnesses = tx["witnesses"]
    data = from_hex(tx_hash(tx))
    idx = [group[0]] + [i for i in group[1:] if i < len(witnesses)]
    for i in idx:
        w = from_hex(witnesses[i])
        data += len(w).to_bytes(8, "little") + w
    for w in witnesses[len(tx["inputs"]):]:
        w = from_hex(w)
        data += len(w).to_bytes(8, "little") + w
    return ckb_blake2b(data)


def sign_input_group(tx, secret, group):
    tx = copy.deepcopy(tx)
    while len(tx["witnesses"]) < len(tx["inputs"]):
        tx["witnesses"].append("0x")
    tx["witnesses"][group[0]] = to_hex(witness_args_bytes(lock=b"\x00" * 65))
    sig = crypto.sign(secret, sighash_all_digest(tx, group))
    tx["witnesses"][group[0]] = to_hex(witness_args_bytes(lock=sig))
    return tx


def _script_size(script):
    return 0 if not script else 33 + len(from_hex(script["args"]))


def occupied_capacity(output, data: bytes) -> int:
    return (8 + _script_size(output["lock"]) + _script_size(output.get("type")) + len(data)) * CKB


class StatCellWriter:
    def __init__(self, store, chain, config, secret):
        self.store, self.chain, self.config, self.secret = store, chain, config, secret
        self.args = to_hex(blake160(crypto.pubkey_from_secret(secret)))

    def lock_script(self):
        c = self.config
        return {"code_hash": c.stat_cell_acp_code_hash,
                "hash_type": c.stat_cell_acp_hash_type, "args": self.args}

    def funding_lock(self):
        c = self.config
        return {"code_hash": c.stat_cell_sighash_code_hash,
                "hash_type": c.stat_cell_sighash_hash_type, "args": self.args}

    def find_stat_cell(self):
        args = self.store.get_meta("stat_cell_type_args")
        if not args:
            return None
        ts = {"code_hash": TYPE_ID_CODE_HASH, "hash_type": "type", "args": args}
        for c in self.chain.get_cells(ts, "type", exact=True):
            return c
        return None

    def publish(self, epoch):
        ep = self.store.get_epoch(epoch)
        if ep is None:
            raise ValueError(f"unknown epoch {epoch}")
        if ep["stat_cell_tx"]:
            return ep["stat_cell_tx"]
        return self._send(ep)

    def _send(self, ep):
        epoch = ep["epoch"]
        data_hex = ep["data_hex"]
        data = from_hex(data_hex)
        existing = self.find_stat_cell()
        if existing is not None:
            tx = self._update_tx(existing, data_hex, data)
        else:
            tx = self._create_tx(data_hex, data)
        h = self.chain.send_transaction(tx)
        if existing is None:
            t = tx["outputs"][0]["type"]
            self.store.set_meta("stat_cell_type_args", t["args"])
            self.store.set_meta("stat_cell_type_hash", script_hash(t))
        try:
            sent_block = self.chain.tip()[0]
        except Exception:
            sent_block = None
        self.store.set_epoch_tx(epoch, h, sent_block)
        return h

    def confirm(self, epoch):
        """Check a sent epoch transaction; returns "published", "wait", "resend" or "idle"."""
        ep = self.store.get_epoch(epoch)
        st = next((x for x in self.store.epoch_states() if x["epoch"] == epoch), None)
        if st is None or not st["stat_cell_tx"]:
            return "idle"
        if st["published"]:
            return "published"
        ep = {**ep, **st}
        try:
            status = self.chain.get_transaction(ep["stat_cell_tx"])["status"]
        except Exception:
            return "wait"
        action = next_action(status, sent_block=ep["sent_block"], tip=self.chain.tip()[0])
        if action == "published":
            self.store.set_epoch_published(epoch)
        elif action == "resend":
            self.store.clear_epoch_tx(epoch)
        return action

    def _update_tx(self, cell, data_hex, data):
        c = self.config
        out = copy.deepcopy(cell["output"])
        cap = int(out["capacity"], 16) - c.stat_cell_fee_shannons
        out["capacity"] = hex(cap)
        if cap < occupied_capacity(out, data):
            raise InsufficientCapacity("stat cell cannot pay the fee")
        tx = {
            "version": "0x0",
            "cell_deps": [{"out_point": {"tx_hash": c.stat_cell_acp_dep_tx,
                                         "index": hex(c.stat_cell_acp_dep_index)},
                           "dep_type": c.stat_cell_acp_dep_type}],
            "header_deps": [],
            "inputs": [{"since": "0x0", "previous_output": cell["out_point"]}],
            "outputs": [out],
            "outputs_data": [data_hex],
            "witnesses": ["0x"],
        }
        return sign_input_group(tx, self.secret, [0])

    def _create_tx(self, data_hex, data):
        c = self.config
        fee = c.stat_cell_fee_shannons
        lock = self.lock_script()
        target = max(c.stat_cell_capacity_ckb * CKB,
                     occupied_capacity({"lock": lock, "type": {"args": "0x" + "00" * 32}}, data))
        inputs, total = [], 0
        for cell in self.chain.get_cells(self.funding_lock(), "lock", exact=True):
            if cell["output"].get("type") or from_hex(cell.get("output_data") or "0x"):
                continue
            inputs.append({"since": "0x0", "previous_output": cell["out_point"]})
            total += int(cell["output"]["capacity"], 16)
            if total >= target + fee + MIN_CHANGE:
                break
        if total < target + fee:
            raise InsufficientFunds(f"have {total} shannons, need {target + fee}")
        change = total - target - fee
        stat_cap = target
        if change < MIN_CHANGE:
            stat_cap += change
        type_script = {"code_hash": TYPE_ID_CODE_HASH, "hash_type": "type",
                       "args": type_id_args(inputs[0], 0)}
        outputs = [{"capacity": hex(stat_cap), "lock": lock, "type": type_script}]
        outputs_data = [data_hex]
        if change >= MIN_CHANGE:
            outputs.append({"capacity": hex(change), "lock": self.funding_lock(), "type": None})
            outputs_data.append("0x")
        tx = {
            "version": "0x0",
            "cell_deps": [{"out_point": {"tx_hash": c.stat_cell_sighash_dep_tx,
                                         "index": hex(c.stat_cell_sighash_dep_index)},
                           "dep_type": "dep_group"}],
            "header_deps": [],
            "inputs": inputs,
            "outputs": outputs,
            "outputs_data": outputs_data,
            "witnesses": ["0x"] * len(inputs),
        }
        return sign_input_group(tx, self.secret, list(range(len(inputs))))
