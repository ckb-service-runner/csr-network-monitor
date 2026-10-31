"""Weekly epochs, Merkle tree and signed epoch data."""
import json

from . import crypto, scoring
from .hashing import ckb_blake2b, from_hex, to_hex
from .store import day_of

EPOCH_SECONDS = 604800
FLAG_PROVISIONAL = 1
FLAG_IDENTITY_MISMATCH = 2
FLAG_BAD_BINDING = 4
FLAG_STAKED = 8          # D29: the runner has a deposited registry stake (apps pick job runners by it)
SCORE_FORMULA_V1 = 1
LEAF_SIZE = 47
UNSIGNED_SIZE = 94
DATA_SIZE = 159
_EPOCH_DOMAIN = b"CSR/v1/epoch"
_THURSDAY_OFFSET = 4 * 86400  # Unix epoch (1970-01-01) is a Thursday


def first_epoch_start(monitor_start) -> int:
    t = int(monitor_start)
    # Mondays are at t ≡ 4 days (mod week)
    r = (t - _THURSDAY_OFFSET) % EPOCH_SECONDS
    return t if r == 0 else t + EPOCH_SECONDS - r


def epoch_bounds(monitor_start, n):
    first = first_epoch_start(monitor_start)
    return first + (n - 1) * EPOCH_SECONDS, first + n * EPOCH_SECONDS


def epoch_at(monitor_start, ts) -> int:
    first = first_epoch_start(monitor_start)
    if ts < first:
        return 0
    return int(ts - first) // EPOCH_SECONDS + 1


def pending_epochs(monitor_start, now, built) -> list:
    built = set(built)
    out = []
    n = 1
    while epoch_bounds(monitor_start, n)[1] <= now:
        if n not in built:
            out.append(n)
        n += 1
    return out


# ---- leaves ----

def encode_leaf(runner_id, *, score, a30, a365, f30, country, asn, flags) -> bytes:
    cc = country.upper() if isinstance(country, str) else ""
    if len(cc) != 2 or not cc.isascii() or not cc.isalpha():
        cc = "??"
    return (from_hex(runner_id)
            + round(score * 100).to_bytes(2, "little")
            + round(a30 * 10000).to_bytes(2, "little")
            + round(a365 * 10000).to_bytes(2, "little")
            + round(f30 * 10000).to_bytes(2, "little")
            + cc.encode("ascii")
            + int(asn or 0).to_bytes(4, "little")
            + bytes([flags]))


def decode_leaf(leaf) -> dict:
    if len(leaf) != LEAF_SIZE:
        raise ValueError("bad leaf length")
    u16 = lambda a: int.from_bytes(leaf[a:a + 2], "little")
    return {"runner_id": to_hex(leaf[:32]), "score": u16(32) / 100,
            "a30": u16(34) / 10000, "a365": u16(36) / 10000, "f30": u16(38) / 10000,
            "country": leaf[40:42].decode("ascii"),
            "asn": int.from_bytes(leaf[42:46], "little"), "flags": leaf[46]}


# ---- Merkle tree ----

def leaf_hash(leaf) -> bytes:
    return ckb_blake2b(b"\x00" + bytes(leaf))


def node_hash(left, right) -> bytes:
    return ckb_blake2b(b"\x01" + bytes(left) + bytes(right))


def _next(level):
    nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
    if len(level) % 2:
        nxt.append(level[-1])
    return nxt


def merkle_root(leaves) -> bytes:
    level = [leaf_hash(l) for l in leaves]
    if not level:
        return b"\x00" * 32
    while len(level) > 1:
        level = _next(level)
    return level[0]


def merkle_proof(leaves, index) -> list:
    level = [leaf_hash(l) for l in leaves]
    if not 0 <= index < len(level):
        raise IndexError("leaf index out of range")
    proof = []
    while len(level) > 1:
        sib = index ^ 1
        if sib < len(level):
            proof.append({"side": "right" if sib > index else "left", "hash": to_hex(level[sib])})
        level = _next(level)
        index //= 2
    return proof


def verify_proof(leaf, proof, root) -> bool:
    try:
        h = leaf_hash(leaf)
        for step in proof:
            sib = from_hex(step["hash"])
            if step["side"] == "left":
                h = node_hash(sib, h)
            elif step["side"] == "right":
                h = node_hash(h, sib)
            else:
                return False
        return h == bytes(root)
    except Exception:
        return False


# ---- epoch data ----

def epoch_unsigned_bytes(*, epoch, start_block, end_block, runner_count, country_count,
                         asn_count, score_formula, merkle_root, prev_epoch_hash) -> bytes:
    if len(merkle_root) != 32 or len(prev_epoch_hash) != 32:
        raise ValueError("hashes must be 32 bytes")
    return (b"\x01" + epoch.to_bytes(4, "little") + start_block.to_bytes(8, "little")
            + end_block.to_bytes(8, "little") + runner_count.to_bytes(4, "little")
            + country_count.to_bytes(2, "little") + asn_count.to_bytes(2, "little")
            + bytes([score_formula]) + bytes(merkle_root) + bytes(prev_epoch_hash))


def sign_epoch_data(secret, unsigned) -> bytes:
    return bytes(unsigned) + crypto.sign(secret, ckb_blake2b(_EPOCH_DOMAIN + bytes(unsigned)))


def verify_epoch_data(data, pubkey) -> bool:
    try:
        if len(data) != DATA_SIZE:
            return False
        return crypto.verify(pubkey, ckb_blake2b(_EPOCH_DOMAIN + bytes(data[:UNSIGNED_SIZE])),
                             bytes(data[UNSIGNED_SIZE:]))
    except Exception:
        return False


def decode_epoch_data(data) -> dict:
    if len(data) != DATA_SIZE:
        raise ValueError("bad epoch data length")
    i = lambda a, b: int.from_bytes(data[a:b], "little")
    return {"version": data[0], "epoch": i(1, 5), "start_block": i(5, 13), "end_block": i(13, 21),
            "runner_count": i(21, 25), "country_count": i(25, 27), "asn_count": i(27, 29),
            "score_formula": data[29], "merkle_root": to_hex(data[30:62]),
            "prev_epoch_hash": to_hex(data[62:94]), "monitor_sig": to_hex(data[94:159])}


# ---- building ----

LATE_AFTER_S = 86400

def build_epoch(store, chain, secret, config, n, *, now):
    existing = store.get_epoch(n)
    if existing is not None:
        return existing["summary"]
    ms = store.get_meta("monitor_start")
    if ms is None:
        raise ValueError("monitor_start is not set")
    start, end = epoch_bounds(int(float(ms)), n)
    if now < end:
        raise ValueError(f"epoch {n} has not ended")
    if n > 1:
        prev = store.get_epoch(n - 1)
        if prev is None:
            raise ValueError(f"epoch {n - 1} is not stored")
        prev_hash = ckb_blake2b(from_hex(prev["data_hex"]))
    else:
        prev_hash = b"\x00" * 32
    ranking = scoring.rank_runners(store, day_of(end - 1), config.provisional_days,
                                    scoring.stake_required(config),
                                    require_identity=getattr(config, "require_identity_proof", False),
                                    now=end - 1)
    items = sorted((i for i in ranking if i["first_seen"] < end),
                   key=lambda i: from_hex(i["runner_id"]))
    leaves = []
    for i in items:
        flags = 0
        if i["provisional"]:
            flags |= FLAG_PROVISIONAL
        if "identity_mismatch" in i["flags"]:
            flags |= FLAG_IDENTITY_MISMATCH
        if "bad_binding" in i["flags"]:
            flags |= FLAG_BAD_BINDING
        if i["stake_status"] == "deposited":
            flags |= FLAG_STAKED
        leaves.append(encode_leaf(i["runner_id"], score=i["score"], a30=i["a30"],
                                  a365=i["a365"], f30=i["f30"], country=i["country"],
                                  asn=i["asn"], flags=flags))
    ranked = [i for i in items if i["rank"] is not None]
    countries = {i["country"] for i in ranked if i["country"] and i["country"] != "??"}
    asns = {i["asn"] for i in ranked if i["asn"]}
    root = merkle_root(leaves)
    start_block = chain.block_at_time(start * 1000)
    end_block = chain.block_at_time(end * 1000 - 1)
    unsigned = epoch_unsigned_bytes(
        epoch=n, start_block=start_block, end_block=end_block, runner_count=len(ranked),
        country_count=len(countries), asn_count=len(asns),
        score_formula=SCORE_FORMULA_V1, merkle_root=root, prev_epoch_hash=prev_hash)
    data = sign_epoch_data(secret, unsigned)
    entries = []
    for idx, leaf in enumerate(leaves):
        e = decode_leaf(leaf)
        e["leaf_hex"] = to_hex(leaf)
        e["proof"] = merkle_proof(leaves, idx)
        entries.append(e)
    summary = {"epoch": n, "start": start, "end": end, "start_block": start_block,
               "end_block": end_block, "runner_count": len(ranked),
               "country_count": len(countries), "asn_count": len(asns),
               "score_formula": scoring.SCORE_FORMULA, "merkle_root": to_hex(root),
               "prev_epoch_hash": to_hex(prev_hash), "data_hex": to_hex(data),
               "monitor_pubkey": to_hex(crypto.pubkey_from_secret(secret)),
               "built_at": int(now), "late": now - end > LATE_AFTER_S, "leaves": entries}
    summary = json.loads(json.dumps(summary))
    store.save_epoch(n, start=start, end=end, merkle_root=summary["merkle_root"],
                     data_hex=summary["data_hex"], summary=summary)
    return summary


def build_pending(store, chain, secret, config, *, now) -> list:
    ms = store.get_meta("monitor_start")
    if ms is None:
        return []
    built = [e["epoch"] for e in store.list_epochs()]
    out = []
    for n in sorted(pending_epochs(int(float(ms)), now, built)):
        build_epoch(store, chain, secret, config, n, now=now)
        out.append(n)
    return out
