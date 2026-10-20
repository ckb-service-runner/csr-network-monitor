"""Fakes for the registration stake (DAO deposit) tests.

FakeChainStake  FakeChainV2 plus get_live_cell(tx_hash, index), answered from `self.live`
dao_live        a `get_live_cell` result for a DAO deposit (or any cell)
DEAD            a `get_live_cell` result for a spent cell
secp_lock       secp256k1_blake160 lock of key n
dual_lock       a csr-dual-lock script with args owner_lock_hash ‖ runner_lock_hash
"""
from csrmon import crypto, molecule
from csrmon.hashing import blake160, to_hex
from fakes_v2 import FakeChainV2

CKB = 10 ** 8
SIGHASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
DAO = {"code_hash": "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e",
       "hash_type": "type", "args": "0x"}
DUAL_LOCK_CODE = "0x" + "e8" * 32
DEAD = {"cell": None, "status": "dead"}


def sk(n):
    return n.to_bytes(32, "big")


def secp_lock(n):
    return {"code_hash": SIGHASH, "hash_type": "type",
            "args": to_hex(blake160(crypto.pubkey_from_secret(sk(n))))}


def dual_lock(owner_n, runner_n=99):
    args = molecule.script_hash(secp_lock(owner_n)) + molecule.script_hash(secp_lock(runner_n))[2:]
    return {"code_hash": DUAL_LOCK_CODE, "hash_type": "data2", "args": args}


def dao_live(owner_n, capacity_ckb, *, data="0x" + "00" * 8, type_=DAO, lock=None):
    return {"cell": {"output": {"capacity": hex(capacity_ckb * CKB), "lock": lock or secp_lock(owner_n),
                                "type": dict(type_) if type_ else None},
                     "data": {"content": data, "hash": "0x" + "00" * 32}},
            "status": "live"}


class FakeChainStake(FakeChainV2):
    def __init__(self, tip=100_000):
        super().__init__(tip)
        self.live = {}          # "0x<tx>:<index>" -> get_live_cell result
        self.live_calls = []

    def get_live_cell(self, tx_hash, index):
        self._check()
        key = f"{tx_hash}:{int(index)}"
        self.live_calls.append(key)
        return self.live.get(key, {"cell": None, "status": "unknown"})
