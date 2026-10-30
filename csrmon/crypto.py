"""secp256k1: signing through libsecp256k1 (coincurve); pure-Python keys and recovery."""
import secrets

try:
    import coincurve
except ImportError as _e:  # no pure-Python fallback for signing
    raise ImportError("csr-network-monitor needs the coincurve package "
                      "(pip install coincurve)") from _e

BACKEND = "libsecp256k1"

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


def sign(secret: bytes, msg32: bytes) -> bytes:
    """RFC 6979 ECDSA, low s, 65 bytes r || s || recid (libsecp256k1)."""
    _check_secret(secret)
    if not isinstance(msg32, (bytes, bytearray)) or len(msg32) != 32:
        raise ValueError("message must be 32 bytes")
    return coincurve.PrivateKey(bytes(secret)).sign_recoverable(bytes(msg32), hasher=None)


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


def verify_ecdsa(pubkey33: bytes, msg32: bytes, sig64: bytes) -> bool:
    """Plain ECDSA verification of a compact r||s signature; high-S is accepted."""
    try:
        pubkey33, msg32, sig64 = bytes(pubkey33), bytes(msg32), bytes(sig64)
        if len(pubkey33) != 33 or pubkey33[0] not in (2, 3) or len(msg32) != 32 or len(sig64) != 64:
            return False
        r = int.from_bytes(sig64[:32], "big")
        s = int.from_bytes(sig64[32:], "big")
        if not 0 < r < N or not 0 < s < N:
            return False
        q = _lift_x(int.from_bytes(pubkey33[1:], "big"), pubkey33[0] & 1)
        z = int.from_bytes(msg32, "big")
        sinv = pow(s, -1, N)
        pt = _affine(_add(_mul(z * sinv % N, G), _mul(r * sinv % N, q)))
        return pt is not None and pt[0] % N == r
    except Exception:
        return False
