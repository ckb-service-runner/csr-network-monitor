"""CSR on-chain formats: attestations, the csr-registry cell (molecule) and the config cell data."""
import re

from . import crypto
from .hashing import ckb_blake2b, from_hex, to_hex

NETWORK_IDS = {"mainnet": 0, "testnet": 1, "devnet": 2}
_ATTEST_PREFIX = b"CSR-ATTEST-v1"
_ATTEST_PREFIX_V2 = b"CSR-ATTEST-v2"
REGISTRY_VERSION = 3


def _u32(n: int) -> bytes:
    return n.to_bytes(4, "little")


def _bytes(b: bytes) -> bytes:
    return _u32(len(b)) + b


def _table(fields) -> bytes:
    header = 4 + 4 * len(fields)
    offsets, pos = [], header
    for f in fields:
        offsets.append(pos)
        pos += len(f)
    return _u32(pos) + b"".join(_u32(o) for o in offsets) + b"".join(fields)


def _split_table(data: bytes, count: int, what: str) -> list:
    if len(data) < 4 or int.from_bytes(data[:4], "little") != len(data):
        raise ValueError(f"{what}: bad total size")
    if len(data) == 4:
        n = 0
    else:
        if len(data) < 8:
            raise ValueError(f"{what}: truncated")
        first = int.from_bytes(data[4:8], "little")
        if first % 4 or first < 8 or first > len(data):
            raise ValueError(f"{what}: bad first offset")
        n = first // 4 - 1
    if n != count:
        raise ValueError(f"{what}: expected {count} fields, got {n}")
    offsets = [int.from_bytes(data[4 + 4 * i:8 + 4 * i], "little") for i in range(n)]
    offsets.append(len(data))
    if n and offsets[0] != 4 + 4 * n:
        raise ValueError(f"{what}: bad first offset")
    for a, b in zip(offsets, offsets[1:]):
        if b < a:
            raise ValueError(f"{what}: offsets not ascending")
    return [data[offsets[i]:offsets[i + 1]] for i in range(n)]


def _read_bytes(b: bytes, what: str) -> bytes:
    if len(b) < 4 or int.from_bytes(b[:4], "little") != len(b) - 4:
        raise ValueError(f"{what}: bad Bytes length")
    return b[4:]


def _fixed(b: bytes, n: int, what: str) -> bytes:
    if len(b) != n:
        raise ValueError(f"{what}: expected {n} bytes")
    return b


def _peer(b: bytes, what: str) -> str:
    try:
        return _read_bytes(b, what).decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{what}: invalid UTF-8") from e


def attestation_body(peer_id: str, service_pubkey: str, network_id: int, expiry_ms: int) -> bytes:
    key = from_hex(service_pubkey)
    if len(key) != 33:
        raise ValueError("service_pubkey must be 33 bytes")
    return _table([_bytes(peer_id.encode("utf-8")), key, bytes([network_id]),
                   int(expiry_ms).to_bytes(8, "little")])


def attestation_message(peer_id: str, service_pubkey: str, network_id: int, expiry_ms: int) -> bytes:
    return ckb_blake2b(_ATTEST_PREFIX + attestation_body(peer_id, service_pubkey, network_id, expiry_ms))


def sign_attestation(secret: bytes, *, peer_id: str, service_pubkey: str, network: str,
                     expiry_ms: int) -> dict:
    if network not in NETWORK_IDS:
        raise ValueError(f"unknown network {network!r}")
    nid = NETWORK_IDS[network]
    sig = crypto.sign(secret, attestation_message(peer_id, service_pubkey, nid, expiry_ms))
    return {"peer_id": peer_id, "service_pubkey": service_pubkey, "network": network,
            "network_id": nid, "expiry_ms": expiry_ms, "signature": to_hex(sig),
            "monitor_pubkey": to_hex(crypto.pubkey_from_secret(secret))}


def verify_attestation(att, monitor_pubkey) -> bool:
    try:
        msg = attestation_message(att["peer_id"], att["service_pubkey"], att["network_id"],
                                  att["expiry_ms"])
        pub = from_hex(monitor_pubkey) if isinstance(monitor_pubkey, str) else bytes(monitor_pubkey)
        return bool(crypto.verify(pub, msg, from_hex(att["signature"])))
    except Exception:
        return False


_OUTPOINT_RE = re.compile(r"0x([0-9a-fA-F]{64}):(0|[1-9][0-9]*)")


def parse_outpoint(s) -> tuple:
    m = _OUTPOINT_RE.fullmatch(s) if isinstance(s, str) else None
    if not m or int(m.group(2)) > 0xFFFFFFFF:
        raise ValueError("bad out point")
    return bytes.fromhex(m.group(1)), int(m.group(2))


def format_outpoint(tx_hash: bytes, index: int) -> str:
    return f"0x{bytes(tx_hash).hex()}:{index}"


def _stake_bytes(s: str) -> bytes:
    tx, i = parse_outpoint(s)
    return tx + _u32(i)


def parse_registry(data: bytes) -> dict:
    f = _split_table(bytes(data), 7, "Registry")
    a = _split_table(f[4], 5, "Attestation")
    att = {"peer_id": _peer(a[0], "attestation.peer_id"),
           "service_pubkey": to_hex(_fixed(a[1], 33, "attestation.service_pubkey")),
           "network_id": _fixed(a[2], 1, "attestation.network")[0],
           "expiry_ms": int.from_bytes(_fixed(a[3], 8, "attestation.expiry_ms"), "little"),
           "signature": to_hex(_fixed(a[4], 65, "attestation.signature"))}
    return {"peer_id": _peer(f[0], "peer_id"),
            "service_pubkey": to_hex(_fixed(f[1], 33, "service_pubkey")),
            "payout_lock_hash": to_hex(_fixed(f[2], 32, "payout_lock_hash")),
            "network": _fixed(f[3], 1, "network")[0],
            "attestation": att,
            "prekeys": to_hex(_read_bytes(f[5], "prekeys")),
            "stake": format_outpoint(_fixed(f[6], 36, "stake")[:32],
                                     int.from_bytes(f[6][32:], "little"))}


def encode_registry(reg: dict) -> bytes:
    att = reg["attestation"]
    a = _table([_bytes(att["peer_id"].encode("utf-8")), from_hex(att["service_pubkey"]),
                bytes([att["network_id"]]), int(att["expiry_ms"]).to_bytes(8, "little"),
                from_hex(att["signature"])])
    return _table([_bytes(reg["peer_id"].encode("utf-8")), from_hex(reg["service_pubkey"]),
                   from_hex(reg["payout_lock_hash"]), bytes([reg["network"]]), a,
                   _bytes(from_hex(reg["prekeys"])), _stake_bytes(reg["stake"])])


def _hash32(h: str, what: str) -> bytes:
    b = from_hex(h)
    if len(b) != 32:
        raise ValueError(f"{what} must be 32 bytes")
    return b


def attestation_body_v2(peer_id: str, service_pubkey: str, network_id: int, expiry_ms: int,
                        stake: str, registry_type_hash: str) -> bytes:
    key = from_hex(service_pubkey)
    if len(key) != 33:
        raise ValueError("service_pubkey must be 33 bytes")
    return _table([_bytes(peer_id.encode("utf-8")), key, bytes([network_id]),
                   int(expiry_ms).to_bytes(8, "little"), _stake_bytes(stake),
                   _hash32(registry_type_hash, "registry_type_hash")])


def attestation_message_v2(peer_id: str, service_pubkey: str, network_id: int, expiry_ms: int,
                           stake: str, registry_type_hash: str) -> bytes:
    """blake2b_ckb("CSR-ATTEST-v2" ‖ AttestationBodyV2) (D21 A)."""
    return ckb_blake2b(_ATTEST_PREFIX_V2 + attestation_body_v2(
        peer_id, service_pubkey, network_id, expiry_ms, stake, registry_type_hash))


def sign_attestation_v2(secret: bytes, *, peer_id: str, service_pubkey: str, network: str,
                        expiry_ms: int, stake: str, registry_type_hash: str) -> dict:
    if network not in NETWORK_IDS:
        raise ValueError(f"unknown network {network!r}")
    nid = NETWORK_IDS[network]
    stake = format_outpoint(*parse_outpoint(stake))
    registry_type_hash = to_hex(_hash32(registry_type_hash, "registry_type_hash"))
    sig = crypto.sign(secret, attestation_message_v2(peer_id, service_pubkey, nid, expiry_ms, stake,
                                                     registry_type_hash))
    return {"version": 2, "peer_id": peer_id, "service_pubkey": service_pubkey, "network": network,
            "network_id": nid, "expiry_ms": expiry_ms, "stake": stake,
            "registry_type_hash": registry_type_hash, "signature": to_hex(sig),
            "monitor_pubkey": to_hex(crypto.pubkey_from_secret(secret))}


def _verify_v2(monitor_pubkey, msg_args, signature) -> bool:
    try:
        msg = attestation_message_v2(*msg_args)
        pub = from_hex(monitor_pubkey) if isinstance(monitor_pubkey, str) else bytes(monitor_pubkey)
        return bool(crypto.verify(pub, msg, from_hex(signature)))
    except Exception:
        return False


def verify_attestation_v2(att, monitor_pubkey) -> bool:
    """Checks a `sign_attestation_v2` reply."""
    try:
        args = (att["peer_id"], att["service_pubkey"], att["network_id"], att["expiry_ms"],
                att["stake"], att["registry_type_hash"])
        return att.get("version") == 2 and _verify_v2(monitor_pubkey, args, att["signature"])
    except Exception:
        return False


def parse_registry_v3(data: bytes) -> dict:
    """Registry v3 cell data; ValueError for anything but a well-formed 10-field table, version 3."""
    f = _split_table(bytes(data), 10, "RegistryV3")
    version = _fixed(f[0], 1, "version")[0]
    if version != REGISTRY_VERSION:
        raise ValueError(f"RegistryV3: version {version}, expected {REGISTRY_VERSION}")
    stake = _fixed(f[5], 36, "stake")
    try:
        endpoint = _read_bytes(f[8], "endpoint").decode("utf-8")
    except UnicodeDecodeError as e:
        raise ValueError("endpoint: invalid UTF-8") from e
    return {"version": version,
            "peer_id": _peer(f[1], "peer_id"),
            "service_pubkey": to_hex(_fixed(f[2], 33, "service_pubkey")),
            "payout_lock_hash": to_hex(_fixed(f[3], 32, "payout_lock_hash")),
            "network": _fixed(f[4], 1, "network")[0],
            "stake": format_outpoint(stake[:32], int.from_bytes(stake[32:], "little")),
            "expiry_ms": int.from_bytes(_fixed(f[6], 8, "expiry_ms"), "little"),
            "attestation_sig": to_hex(_fixed(f[7], 65, "attestation_sig")),
            "endpoint": endpoint,
            "prekeys": to_hex(_read_bytes(f[9], "prekeys"))}


def encode_registry_v3(reg: dict) -> bytes:
    sig = from_hex(reg["attestation_sig"])
    if len(sig) != 65:
        raise ValueError("attestation_sig must be 65 bytes")
    return _table([bytes([REGISTRY_VERSION]), _bytes(reg["peer_id"].encode("utf-8")),
                   from_hex(reg["service_pubkey"]), _hash32(reg["payout_lock_hash"], "payout_lock_hash"),
                   bytes([reg["network"]]), _stake_bytes(reg["stake"]),
                   int(reg["expiry_ms"]).to_bytes(8, "little"), sig,
                   _bytes(reg.get("endpoint", "").encode("utf-8")),
                   _bytes(from_hex(reg.get("prekeys", "0x")))])


def verify_registry_v3(reg, monitor_pubkey, registry_type_hash) -> bool:
    """True when `attestation_sig` is this monitor's CSR-ATTEST-v2 signature over the cell's
    peer_id, service_pubkey, network, expiry_ms, stake and the given registry type hash."""
    try:
        args = (reg["peer_id"], reg["service_pubkey"], reg["network"], reg["expiry_ms"],
                reg["stake"], registry_type_hash)
        return _verify_v2(monitor_pubkey, args, reg["attestation_sig"])
    except Exception:
        return False


def config_cell_data(monitor_pubkey: bytes, clock_ms: int) -> bytes:
    if len(monitor_pubkey) != 33:
        raise ValueError("monitor_pubkey must be 33 bytes")
    return bytes(monitor_pubkey) + int(clock_ms).to_bytes(8, "little") + b"\x00" * 8


def parse_config_cell(data: bytes) -> dict:
    if len(data) < 41:
        raise ValueError("config cell data too short")
    return {"monitor_pubkey": to_hex(data[:33]),
            "clock_ms": int.from_bytes(data[33:41], "little")}
