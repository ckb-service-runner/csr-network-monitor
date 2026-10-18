"""Phase 2 acceptance: wire protocol, signatures, registration cell codec."""
import hashlib
import json

import pytest

from csrmon import protocol, crypto, base58
from csrmon.hashing import ckb_blake2b, to_hex, from_hex


def sk(n):
    return n.to_bytes(32, "big")


MON = sk(11)
SVC = sk(22)
P2P = sk(33)


def test_runner_id():
    pk = crypto.pubkey_from_secret(SVC)
    rid = protocol.runner_id(pk)
    assert rid == "0x" + ckb_blake2b(pk).hex()
    assert len(rid) == 66


def test_peer_id_from_pubkey():
    pk = crypto.pubkey_from_secret(P2P)
    pid = protocol.peer_id_from_pubkey(pk)
    raw = base58.b58decode(pid)
    assert raw == b"\x12\x20" + hashlib.sha256(pk).digest()
    assert pid.startswith("Qm")


def test_canonical_json():
    assert protocol.canonical_json({"b": 1, "a": [1, 2], "c": "é"}) == \
        '{"a":[1,2],"b":1,"c":"é"}'.encode("utf-8")


def test_domains():
    assert protocol.DOMAIN_CHALLENGE == b"CSR/v1/challenge"
    assert protocol.DOMAIN_PROBE == b"CSR/v1/probe"
    assert protocol.DOMAIN_BIND == b"CSR/v1/bind"
    assert protocol.DOMAIN_CHECKIN == b"CSR/v1/checkin"
    assert protocol.DOMAIN_EPOCH == b"CSR/v1/epoch"


def make_ch(**kw):
    args = dict(network="testnet", monitor_tip=1000, block_height=950,
                issued_at=1760806800, nonce=b"\x07" * 32)
    args.update(kw)
    return protocol.make_challenge(MON, **args)


def test_make_challenge_shape_and_sig():
    ch = make_ch()
    assert set(ch) == {"v", "network", "nonce", "issued_at", "monitor_tip",
                       "block_height", "monitor_sig"}
    assert ch["v"] == 1 and ch["network"] == "testnet"
    assert ch["nonce"] == "0x" + "07" * 32
    assert ch["monitor_tip"] == 1000 and ch["block_height"] == 950
    unsigned = {k: v for k, v in ch.items() if k != "monitor_sig"}
    digest = ckb_blake2b(b"CSR/v1/challenge" + protocol.canonical_json(unsigned))
    assert crypto.verify(crypto.pubkey_from_secret(MON), digest, from_hex(ch["monitor_sig"]))
    assert protocol.verify_challenge(ch, crypto.pubkey_from_secret(MON))


def test_make_challenge_random_nonce():
    a = protocol.make_challenge(MON, network="testnet", monitor_tip=5, block_height=1, issued_at=1)
    b = protocol.make_challenge(MON, network="testnet", monitor_tip=5, block_height=1, issued_at=1)
    assert a["nonce"] != b["nonce"] and len(from_hex(a["nonce"])) == 32


def test_verify_challenge_rejects():
    ch = make_ch()
    pk = crypto.pubkey_from_secret(MON)
    bad = dict(ch, monitor_tip=1001)
    assert not protocol.verify_challenge(bad, pk)
    assert not protocol.verify_challenge(ch, crypto.pubkey_from_secret(SVC))
    assert not protocol.verify_challenge({"v": 1}, pk)
    assert not protocol.verify_challenge(dict(ch, monitor_sig="0xzz"), pk)


FIELDS = dict(peer_id="QmPeer", tip_number=999, tip_hash="0x" + "aa" * 32,
              block_hash="0x" + "bb" * 32, ibd=False, peers_out=8,
              csr_version="0.1.0", ckb_version="0.203.0")


def test_sign_response_shape_and_digest():
    ch = make_ch()
    r = protocol.sign_response(SVC, ch, **FIELDS)
    assert r["v"] == 1 and r["nonce"] == ch["nonce"]
    for k, v in FIELDS.items():
        assert r[k] == v
    assert set(r) == {"v", "nonce", "sig", *FIELDS}
    unsigned = {k: v for k, v in r.items() if k != "sig"}
    digest = ckb_blake2b(b"CSR/v1/probe"
                         + ckb_blake2b(protocol.canonical_json(ch))
                         + ckb_blake2b(protocol.canonical_json(unsigned)))
    assert protocol.response_digest(ch, r) == digest
    pk = crypto.pubkey_from_secret(SVC)
    assert crypto.verify(pk, digest, from_hex(r["sig"]))
    assert protocol.verify_response_sig(ch, r, pk)


def test_verify_response_sig_rejects():
    ch = make_ch()
    pk = crypto.pubkey_from_secret(SVC)
    r = protocol.sign_response(SVC, ch, **FIELDS)
    assert not protocol.verify_response_sig(ch, dict(r, tip_number=1000), pk)
    assert not protocol.verify_response_sig(make_ch(nonce=b"\x08" * 32), r, pk)
    assert not protocol.verify_response_sig(ch, r, crypto.pubkey_from_secret(MON))
    assert not protocol.verify_response_sig(ch, {"nonce": "x"}, pk)


def test_bind():
    svc_pk = crypto.pubkey_from_secret(SVC)
    p2p_pk = crypto.pubkey_from_secret(P2P)
    d = protocol.bind_digest(svc_pk, "testnet")
    assert d == ckb_blake2b(b"CSR/v1/bind" + svc_pk + b"testnet")
    sig = protocol.sign_bind(P2P, svc_pk, "testnet")
    assert protocol.verify_bind(p2p_pk, svc_pk, "testnet", sig)
    assert not protocol.verify_bind(p2p_pk, svc_pk, "mainnet", sig)
    assert not protocol.verify_bind(svc_pk, svc_pk, "testnet", sig)


def test_checkin():
    svc_pk = crypto.pubkey_from_secret(SVC)
    body = protocol.make_checkin(SVC, "testnet", 1760806800)
    assert body["v"] == 1 and body["ts"] == 1760806800
    assert body["runner_id"] == protocol.runner_id(svc_pk)
    d = protocol.checkin_digest("testnet", body["runner_id"], 1760806800)
    assert d == ckb_blake2b(b"CSR/v1/checkin" + b"testnet"
                            + from_hex(body["runner_id"]) + (1760806800).to_bytes(8, "little"))
    assert protocol.verify_checkin(body, svc_pk, "testnet")
    assert not protocol.verify_checkin(body, svc_pk, "mainnet")
    assert not protocol.verify_checkin(dict(body, ts=1760806801), svc_pk, "testnet")
    assert not protocol.verify_checkin({"ts": 1}, svc_pk, "testnet")


# ---------- registration cell ----------

def make_reg(**kw):
    svc_pk = crypto.pubkey_from_secret(SVC)
    p2p_pk = crypto.pubkey_from_secret(P2P)
    args = dict(network="testnet", mode="pull", ranking_opt_in=True,
                service_pubkey=svc_pk, p2p_pubkey=p2p_pk,
                bind_sig=protocol.sign_bind(P2P, svc_pk, kw.get("network", "testnet")),
                p2p_port=8115, endpoint="https://runner.example.org:8443")
    args.update(kw)
    return protocol.Registration(**args)


def test_registration_layout():
    reg = make_reg()
    data = protocol.encode_registration(reg)
    ep = b"https://runner.example.org:8443"
    assert len(data) == 139 + len(ep)
    assert data[0] == 1          # version
    assert data[1] == 0          # testnet
    assert data[2] == 0          # pull
    assert data[3] == 1          # flags: ranking opt-in
    assert data[4:37] == reg.service_pubkey
    assert data[37:70] == reg.p2p_pubkey
    assert data[70:135] == reg.bind_sig
    assert data[135:137] == (8115).to_bytes(2, "little")
    assert data[137:139] == len(ep).to_bytes(2, "little")
    assert data[139:] == ep


def test_registration_roundtrip_and_properties():
    reg = make_reg(mode="push", endpoint="", p2p_port=0, ranking_opt_in=False)
    data = protocol.encode_registration(reg)
    assert data[2] == 1 and data[3] == 0 and len(data) == 139
    back = protocol.decode_registration(data)
    assert back == reg
    assert back.runner_id == protocol.runner_id(reg.service_pubkey)
    assert back.peer_id == protocol.peer_id_from_pubkey(reg.p2p_pubkey)


def test_registration_mainnet_byte():
    reg = make_reg(network="mainnet")
    data = protocol.encode_registration(reg)
    assert data[1] == 1
    assert protocol.decode_registration(data).network == "mainnet"


def _mutate(data, idx, value):
    b = bytearray(data)
    b[idx] = value
    return bytes(b)


def test_registration_decode_errors():
    good = protocol.encode_registration(make_reg())
    bad_inputs = [
        b"",
        good[:100],
        _mutate(good, 0, 2),                 # version
        _mutate(good, 1, 7),                 # network
        _mutate(good, 2, 5),                 # mode
        _mutate(good, 3, 3),                 # unknown flag bit
        _mutate(good, 80, good[80] ^ 1),     # bind signature broken
        good + b"x",                         # trailing byte
    ]
    for data in bad_inputs:
        with pytest.raises(protocol.RegistrationError):
            protocol.decode_registration(data)


def test_registration_pull_needs_endpoint_and_push_has_none():
    with pytest.raises(protocol.RegistrationError):
        protocol.decode_registration(protocol.encode_registration(make_reg(endpoint="")))
    with pytest.raises(protocol.RegistrationError):
        protocol.decode_registration(protocol.encode_registration(
            make_reg(mode="push", endpoint="https://x.example")))


def test_registration_bind_for_other_network_rejected():
    svc_pk = crypto.pubkey_from_secret(SVC)
    reg = make_reg(network="mainnet", bind_sig=protocol.sign_bind(P2P, svc_pk, "testnet"))
    with pytest.raises(protocol.RegistrationError):
        protocol.decode_registration(protocol.encode_registration(reg))
