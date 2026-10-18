"""Molecule encoding of CKB types and transaction hashing."""
from .hashing import ckb_blake2b, from_hex, to_hex

HASH_TYPES = {"data": 0, "type": 1, "data1": 2, "data2": 4}
DEP_TYPES = {"code": 0, "dep_group": 1}


def _u32(n):
    return int(n).to_bytes(4, "little")


def _u64(n):
    return int(n).to_bytes(8, "little")


def _int(v):
    return int(v, 16) if isinstance(v, str) else int(v)


def fixvec(items):
    return _u32(len(items)) + b"".join(items)


def dynvec(items):
    """Molecule dynvec / table: total size, offsets, items."""
    if not items:
        return _u32(4)
    header = 4 + 4 * len(items)
    offsets, pos = [], header
    for it in items:
        offsets.append(_u32(pos))
        pos += len(it)
    return _u32(pos) + b"".join(offsets) + b"".join(items)


def bytes_(data: bytes) -> bytes:
    return fixvec([bytes([b]) for b in data])


def _bytes_enc(data: bytes) -> bytes:
    return _u32(len(data)) + data


def script_bytes(script) -> bytes:
    return dynvec([from_hex(script["code_hash"]),
                   bytes([HASH_TYPES[script["hash_type"]]]),
                   _bytes_enc(from_hex(script["args"]))])


def script_hash(script) -> str:
    return to_hex(ckb_blake2b(script_bytes(script)))


def out_point_bytes(op) -> bytes:
    return from_hex(op["tx_hash"]) + _u32(_int(op["index"]))


def cell_input_bytes(inp) -> bytes:
    return _u64(_int(inp["since"])) + out_point_bytes(inp["previous_output"])


def cell_dep_bytes(dep) -> bytes:
    return out_point_bytes(dep["out_point"]) + bytes([DEP_TYPES[dep["dep_type"]]])


def cell_output_bytes(out) -> bytes:
    t = out.get("type")
    return dynvec([_u64(_int(out["capacity"])), script_bytes(out["lock"]),
                   script_bytes(t) if t else b""])


def raw_transaction_bytes(tx) -> bytes:
    return dynvec([
        _u32(_int(tx["version"])),
        fixvec([cell_dep_bytes(d) for d in tx["cell_deps"]]),
        fixvec([from_hex(h) for h in tx["header_deps"]]),
        fixvec([cell_input_bytes(i) for i in tx["inputs"]]),
        dynvec([cell_output_bytes(o) for o in tx["outputs"]]),
        dynvec([_bytes_enc(from_hex(d)) for d in tx["outputs_data"]]),
    ])


def transaction_bytes(tx) -> bytes:
    return dynvec([raw_transaction_bytes(tx),
                   dynvec([_bytes_enc(from_hex(w)) for w in tx["witnesses"]])])


def tx_hash(tx) -> str:
    return to_hex(ckb_blake2b(raw_transaction_bytes(tx)))


def witness_args_bytes(lock=None, input_type=None, output_type=None) -> bytes:
    return dynvec([b"" if v is None else _bytes_enc(bytes(v))
                   for v in (lock, input_type, output_type)])
