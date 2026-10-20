"""Stake check: is a registration backed by a live Nervos DAO deposit?"""
from . import molecule
from .csrchain import format_outpoint, parse_outpoint

CKB = 10**8
DAO_TYPE_SCRIPT = {"code_hash": "0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e",
                   "hash_type": "type", "args": "0x"}


def _result(status, capacity_ckb, reason):
    return {"status": status, "capacity_ckb": capacity_ckb, "reason": reason}


def _is_dao(t) -> bool:
    if not isinstance(t, dict):
        return False
    try:
        return (str(t["code_hash"]).lower() == DAO_TYPE_SCRIPT["code_hash"]
                and t["hash_type"] == DAO_TYPE_SCRIPT["hash_type"]
                and str(t["args"]).lower() == DAO_TYPE_SCRIPT["args"])
    except KeyError:
        return False


def check_stake(chain, outpoint, *, min_stake_ckb, owner_lock_hash=None) -> dict:
    tx_hash, index = parse_outpoint(outpoint)
    res = chain.get_live_cell(format_outpoint(tx_hash, index)[:66], index)
    status = res.get("status") if isinstance(res, dict) else None
    if status == "dead":
        return _result("withdrawn", None, "spent")
    cell = res.get("cell") if isinstance(res, dict) else None
    if status != "live" or not cell:
        return _result("invalid", None, "not_found")
    out = cell["output"]
    shannons = int(out["capacity"], 16)
    cap = shannons // CKB
    if not _is_dao(out.get("type")):
        return _result("invalid", cap, "not_dao")
    data = ((cell.get("data") or {}).get("content") or "0x").lower()
    if data != "0x" + "00" * 8:
        return _result("invalid", cap, "not_deposit")
    if shannons < min_stake_ckb * CKB:
        return _result("invalid", cap, "too_small")
    if owner_lock_hash is not None and \
            molecule.script_hash(out["lock"]).lower() != owner_lock_hash.lower():
        return _result("invalid", cap, "wrong_owner")
    return _result("deposited", cap, None)
