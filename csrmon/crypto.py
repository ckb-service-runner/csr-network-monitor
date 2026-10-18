"""Pure-Python secp256k1: keys, RFC 6979 signatures, recovery."""
import hashlib
import hmac
import secrets

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

# Jacobian coordinates (X, Y, Z); infinity has Z == 0.
_INF = (1, 1, 0)


def _dbl(p):
    x, y, z = p
    if z == 0 or y == 0:
        return _INF
    s = 4 * x * y * y % P
    m = 3 * x * x % P
    nx = (m * m - 2 * s) % P
    return nx, (m * (s - nx) - 8 * pow(y, 4, P)) % P, 2 * y * z % P


def _add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1s, z2s = z1 * z1 % P, z2 * z2 % P
    u1, u2 = x1 * z2s % P, x2 * z1s % P
    s1, s2 = y1 * z2s * z2 % P, y2 * z1s * z1 % P
    if u1 == u2:
        return _dbl(p) if s1 == s2 else _INF
    h, r = u2 - u1, s2 - s1
    h2 = h * h % P
    h3 = h * h2 % P
    v = u1 * h2 % P
    nx = (r * r - h3 - 2 * v) % P
    return nx, (r * (v - nx) - s1 * h3) % P, h * z1 * z2 % P


def _mul(k, pt):
    r = _INF
    q = (pt[0], pt[1], 1)
    while k:
        if k & 1:
            r = _add(r, q)
        q = _dbl(q)
        k >>= 1
    return r


def _affine(p):
    if p[2] == 0:
        return None
    zi = pow(p[2], -1, P)
    zi2 = zi * zi % P
    return p[0] * zi2 % P, p[1] * zi2 * zi % P


def _lift_x(x, odd):
    if not 0 <= x < P:
        raise ValueError("x out of range")
    y = pow((x * x * x + 7) % P, (P + 1) // 4, P)
    if y * y % P != (x * x * x + 7) % P:
        raise ValueError("point not on curve")
    if (y & 1) != odd:
        y = P - y
    return x, y


def _check_secret(secret):
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    d = int.from_bytes(secret, "big")
    if not 0 < d < N:
        raise ValueError("secret out of range")
    return d


def _compress(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def generate_secret() -> bytes:
    while True:
        d = secrets.randbelow(N)
        if d:
            return d.to_bytes(32, "big")


def pubkey_from_secret(secret: bytes) -> bytes:
    d = _check_secret(secret)
    return _compress(_affine(_mul(d, G)))


def _rfc6979(d, z):
    x = d.to_bytes(32, "big")
    h1 = (z % N).to_bytes(32, "big")
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h1, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 0 < t < N:
            yield t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(secret: bytes, msg32: bytes) -> bytes:
    d = _check_secret(secret)
    if not isinstance(msg32, (bytes, bytearray)) or len(msg32) != 32:
        raise ValueError("message must be 32 bytes")
    z = int.from_bytes(msg32, "big")
    for k in _rfc6979(d, z):
        rx, ry = _affine(_mul(k, G))
        r = rx % N
        if r == 0:
            continue
        s = pow(k, -1, N) * (z + r * d) % N
        if s == 0:
            continue
        recid = (ry & 1) | (2 if rx >= N else 0)
        if s > N // 2:
            s = N - s
            recid ^= 1
        return r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes([recid])


def recover(msg32: bytes, sig65: bytes) -> bytes:
    if len(msg32) != 32 or len(sig65) != 65:
        raise ValueError("bad input length")
    r = int.from_bytes(sig65[:32], "big")
    s = int.from_bytes(sig65[32:64], "big")
    recid = sig65[64]
    if recid > 3 or not 0 < r < N or not 0 < s < N:
        raise ValueError("invalid signature")
    x = r + N if recid & 2 else r
    R = _lift_x(x, recid & 1)
    z = int.from_bytes(msg32, "big")
    rinv = pow(r, -1, N)
    a = _mul(s * rinv % N, R)
    b = _mul((-z * rinv) % N, G)
    q = _affine(_add(a, b))
    if q is None:
        raise ValueError("invalid signature")
    return _compress(q)


def verify(pubkey33: bytes, msg32: bytes, sig65: bytes) -> bool:
    try:
        if len(sig65) != 65 or int.from_bytes(sig65[32:64], "big") > N // 2:
            return False
        return recover(msg32, sig65) == bytes(pubkey33)
    except Exception:
        return False
