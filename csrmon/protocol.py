"""Wire protocol: challenge, response, key binding, check-in, registration cell."""
import hashlib
import json
import secrets
from dataclasses import dataclass

from . import crypto
from .base58 import b58encode
from .hashing import ckb_blake2b, from_hex, to_hex

DOMAIN_CHALLENGE = b"CSR/v1/challenge"
DOMAIN_PROBE = b"CSR/v1/probe"
DOMAIN_BIND = b"CSR/v1/bind"
DOMAIN_CHECKIN = b"CSR/v1/checkin"
DOMAIN_EPOCH = b"CSR/v1/epoch"


def runner_id(service_pubkey: bytes) -> str:
    return to_hex(ckb_blake2b(service_pubkey))


def peer_id_from_pubkey(p2p_pubkey: bytes) -> str:
    return b58encode(b"\x12\x20" + hashlib.sha256(p2p_pubkey).digest())


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


# ---- challenge ----

def _challenge_digest(unsigned: dict) -> bytes:
    return ckb_blake2b(DOMAIN_CHALLENGE + canonical_json(unsigned))


def make_challenge(secret, *, network, monitor_tip, block_height, issued_at, nonce=None) -> dict:
    if nonce is None:
        nonce = secrets.token_bytes(32)
    ch = {"v": 1, "network": network, "nonce": to_hex(nonce), "issued_at": issued_at,
          "monitor_tip": monitor_tip, "block_height": block_height}
    ch["monitor_sig"] = to_hex(crypto.sign(secret, _challenge_digest(ch)))
    return ch


def verify_challenge(challenge, monitor_pubkey) -> bool:
    try:
        unsigned = {k: v for k, v in challenge.items() if k != "monitor_sig"}
        sig = from_hex(challenge["monitor_sig"])
        return crypto.verify(monitor_pubkey, _challenge_digest(unsigned), sig)
    except Exception:
        return False


# ---- response ----

def response_digest(challenge, response) -> bytes:
    unsigned = {k: v for k, v in response.items() if k != "sig"}
    return ckb_blake2b(DOMAIN_PROBE + ckb_blake2b(canonical_json(challenge))
                       + ckb_blake2b(canonical_json(unsigned)))


def sign_response(service_secret, challenge, *, peer_id, tip_number, tip_hash, block_hash,
                  ibd, peers_out, csr_version, ckb_version) -> dict:
    resp = {"v": 1, "nonce": challenge["nonce"], "peer_id": peer_id,
            "tip_number": tip_number, "tip_hash": tip_hash, "block_hash": block_hash,
            "ibd": ibd, "peers_out": peers_out, "csr_version": csr_version,
            "ckb_version": ckb_version}
    resp["sig"] = to_hex(crypto.sign(service_secret, response_digest(challenge, resp)))
    return resp


def verify_response_sig(challenge, response, service_pubkey) -> bool:
    try:
        return crypto.verify(service_pubkey, response_digest(challenge, response),
                             from_hex(response["sig"]))
    except Exception:
        return False


# ---- key binding ----

def bind_digest(service_pubkey: bytes, network: str) -> bytes:
    return ckb_blake2b(DOMAIN_BIND + service_pubkey + network.encode())


def sign_bind(p2p_secret, service_pubkey: bytes, network: str) -> bytes:
    return crypto.sign(p2p_secret, bind_digest(service_pubkey, network))


def verify_bind(p2p_pubkey, service_pubkey, network, sig) -> bool:
    try:
        return crypto.verify(p2p_pubkey, bind_digest(service_pubkey, network), sig)
    except Exception:
        return False


# ---- check-in ----

def checkin_digest(network: str, runner_id: str, ts: int) -> bytes:
    return ckb_blake2b(DOMAIN_CHECKIN + network.encode() + from_hex(runner_id)
                       + ts.to_bytes(8, "little"))


def make_checkin(service_secret, network, ts) -> dict:
    rid = runner_id(crypto.pubkey_from_secret(service_secret))
    sig = crypto.sign(service_secret, checkin_digest(network, rid, ts))
    return {"v": 1, "runner_id": rid, "ts": ts, "sig": to_hex(sig)}


def verify_checkin(body, service_pubkey, network) -> bool:
    try:
        ts = body["ts"]
        if not isinstance(ts, int) or isinstance(ts, bool):
            return False
        rid = body["runner_id"]
        if rid != runner_id(service_pubkey):
            return False
        return crypto.verify(service_pubkey, checkin_digest(network, rid, ts),
                             from_hex(body["sig"]))
    except Exception:
        return False


# ---- registration cell ----

class RegistrationError(Exception):
    pass


_NETWORKS = {0: "testnet", 1: "mainnet"}
_NETWORK_BYTES = {v: k for k, v in _NETWORKS.items()}
_MODES = {0: "pull", 1: "push"}
_MODE_BYTES = {v: k for k, v in _MODES.items()}
_HEADER = 139


@dataclass
class Registration:
    network: str
    mode: str
    ranking_opt_in: bool
    service_pubkey: bytes
    p2p_pubkey: bytes
    bind_sig: bytes
    p2p_port: int
    endpoint: str

    @property
    def runner_id(self) -> str:
        return runner_id(self.service_pubkey)

    @property
    def peer_id(self) -> str:
        return peer_id_from_pubkey(self.p2p_pubkey)


def encode_registration(reg: Registration) -> bytes:
    ep = reg.endpoint.encode("utf-8")
    return (bytes([1, _NETWORK_BYTES[reg.network], _MODE_BYTES[reg.mode],
                   1 if reg.ranking_opt_in else 0])
            + reg.service_pubkey + reg.p2p_pubkey + reg.bind_sig
            + reg.p2p_port.to_bytes(2, "little") + len(ep).to_bytes(2, "little") + ep)


def decode_registration(data: bytes) -> Registration:
    data = bytes(data)
    if len(data) < _HEADER:
        raise RegistrationError("too short")
    if data[0] != 1:
        raise RegistrationError("unsupported version")
    if data[1] not in _NETWORKS:
        raise RegistrationError("unknown network")
    if data[2] not in _MODES:
        raise RegistrationError("unknown mode")
    if data[3] & ~1:
        raise RegistrationError("unknown flag bits")
    n = int.from_bytes(data[137:139], "little")
    if len(data) != _HEADER + n:
        raise RegistrationError("length mismatch")
    try:
        endpoint = data[139:].decode("utf-8")
    except UnicodeDecodeError:
        raise RegistrationError("endpoint is not valid UTF-8")
    network, mode = _NETWORKS[data[1]], _MODES[data[2]]
    if mode == "pull" and not endpoint:
        raise RegistrationError("pull mode requires an endpoint")
    if mode == "push" and endpoint:
        raise RegistrationError("push mode must not have an endpoint")
    svc, p2p, sig = data[4:37], data[37:70], data[70:135]
    if not verify_bind(p2p, svc, network, sig):
        raise RegistrationError("bind signature invalid")
    return Registration(network, mode, bool(data[3] & 1), svc, p2p, sig,
                        int.from_bytes(data[135:137], "little"), endpoint)
