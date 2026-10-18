"""CSR ping protocol v1 primitives (spec/ping-protocol.md)."""
import hashlib
import re
import secrets

from . import crypto
from .hashing import from_hex, to_hex

ANSWER_FIELDS = ("nonce", "peer_id", "service_pubkey", "binding_sig", "network", "csr_version",
                 "node_version", "r2_state", "tip_number", "tip_hash", "block_hash_at_height",
                 "uptime_s", "ping_mode")
FRESHNESS_S = 60
CHECKIN_FIELDS = ("peer_id", "service_pubkey", "binding_sig", "network", "csr_version")
_NONCE_RE = re.compile(r"0x[0-9a-f]{64}")
_INT_FIELDS = ("tip_number", "uptime_s")


def valid_nonce(n) -> bool:
    return isinstance(n, str) and _NONCE_RE.fullmatch(n) is not None


def challenge_message(nonce, height, issued_at) -> str:
    return f"CSR-PING-CHALLENGE-v1\n{nonce}\n{height}\n{issued_at}"


def binding_message(peer_id, service_pubkey, network) -> str:
    return f"CSR-BINDING-v1\n{peer_id}\n{service_pubkey}\n{network}"


def answer_message(answer: dict) -> str:
    return "CSR-PING-ANSWER-v1\n" + "\n".join(str(answer[k]) for k in ANSWER_FIELDS)


def _digest(message: str) -> bytes:
    return hashlib.sha256(message.encode("utf-8")).digest()


def sign(secret: bytes, message: str) -> str:
    return to_hex(crypto.sign(secret, _digest(message))[:64])


def verify(pubkey, message, sig_hex) -> bool:
    try:
        if not isinstance(sig_hex, str) or not sig_hex.startswith("0x"):
            return False
        pk = from_hex(pubkey) if isinstance(pubkey, str) else bytes(pubkey)
        sig = from_hex(sig_hex)
        return crypto.verify_ecdsa(pk, _digest(message), sig)
    except Exception:
        return False


def verify_binding(peer_id, service_pubkey, network, sig) -> bool:
    return verify(service_pubkey, binding_message(peer_id, service_pubkey, network), sig)


def make_challenge(secret: bytes, *, height: int, issued_at: int, nonce=None) -> dict:
    nonce_hex = to_hex(nonce if nonce is not None else secrets.token_bytes(32))
    return {"nonce": nonce_hex, "height": height, "issued_at": issued_at,
            "monitor_sig": sign(secret, challenge_message(nonce_hex, height, issued_at))}


def verify_challenge(challenge, monitor_pubkey) -> bool:
    try:
        return verify(monitor_pubkey,
                      challenge_message(challenge["nonce"], challenge["height"],
                                        challenge["issued_at"]),
                      challenge["monitor_sig"])
    except Exception:
        return False


def make_answer(service_secret: bytes, challenge: dict, *, peer_id, network, csr_version,
                node_version, r2_state, tip_number, tip_hash, block_hash_at_height, uptime_s,
                ping_mode) -> dict:
    pub = to_hex(crypto.pubkey_from_secret(service_secret))
    answer = {
        "nonce": challenge["nonce"], "peer_id": peer_id, "service_pubkey": pub,
        "binding_sig": sign(service_secret, binding_message(peer_id, pub, network)),
        "network": network, "csr_version": csr_version, "node_version": node_version,
        "r2_state": r2_state, "tip_number": tip_number, "tip_hash": tip_hash,
        "block_hash_at_height": block_hash_at_height, "uptime_s": uptime_s,
        "ping_mode": ping_mode,
    }
    return {"answer": answer, "sig": sign(service_secret, answer_message(answer))}


def parse_answer(body):
    if not isinstance(body, dict) or set(body) != {"answer", "sig"}:
        raise ValueError("body must have exactly answer and sig")
    answer, sig = body["answer"], body["sig"]
    if not isinstance(answer, dict) or set(answer) != set(ANSWER_FIELDS):
        raise ValueError("answer must have exactly the 13 fields")
    for k in ANSWER_FIELDS:
        v = answer[k]
        if k in _INT_FIELDS:
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise ValueError(f"{k} must be a non-negative integer")
        elif not isinstance(v, str):
            raise ValueError(f"{k} must be a string")
    if not isinstance(sig, str):
        raise ValueError("sig must be a string")
    return {k: answer[k] for k in ANSWER_FIELDS}, sig


def parse_checkin(body) -> dict:
    if not isinstance(body, dict):
        raise ValueError("check-in must be an object")
    out = {}
    for k in CHECKIN_FIELDS:
        if not isinstance(body.get(k), str):
            raise ValueError(f"{k} must be a string")
        out[k] = body[k]
    return out
