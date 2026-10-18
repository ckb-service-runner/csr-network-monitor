"""Bitcoin base58."""
_ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_INDEX = {c: i for i, c in enumerate(_ALPHA)}


def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _ALPHA[r] + out
    zeros = len(b) - len(b.lstrip(b"\x00"))
    return "1" * zeros + out


def b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _INDEX:
            raise ValueError("invalid base58 character")
        n = n * 58 + _INDEX[c]
    zeros = len(s) - len(s.lstrip("1"))
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * zeros + body
