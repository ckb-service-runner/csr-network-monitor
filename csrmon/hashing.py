"""Hashing and hex helpers."""
import hashlib

_PERSONAL = b"ckb-default-hash"


def ckb_blake2b(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32, person=_PERSONAL).digest()


def blake160(data: bytes) -> bytes:
    return ckb_blake2b(data)[:20]


def to_hex(b: bytes) -> str:
    return "0x" + bytes(b).hex()


def from_hex(s: str) -> bytes:
    if s[:2] in ("0x", "0X"):
        s = s[2:]
    if len(s) % 2:
        raise ValueError("odd-length hex string")
    try:
        return bytes.fromhex(s)
    except ValueError as e:
        raise ValueError("invalid hex string") from e
