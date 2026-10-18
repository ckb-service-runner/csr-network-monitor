"""v2 Phase 2 acceptance: CSR ping protocol v1 primitives (csrmon/ping.py).

Every expected signature below was produced by CSR's own Rust code; deterministic RFC 6979
signing must reproduce it byte for byte.
"""
import pytest

import csr_vectors as V
from csrmon import ping, crypto
from csrmon.hashing import from_hex

N = crypto.N


def secret(h):
    return from_hex(h)


def high_s(sig_hex):
    raw = from_hex(sig_hex)
    s = int.from_bytes(raw[32:64], "big")
    return "0x" + (raw[:32] + (N - s).to_bytes(32, "big")).hex()


def test_constants():
    assert ping.ANSWER_FIELDS == (
        "nonce", "peer_id", "service_pubkey", "binding_sig", "network", "csr_version",
        "node_version", "r2_state", "tip_number", "tip_hash", "block_hash_at_height",
        "uptime_s", "ping_mode")
    assert ping.FRESHNESS_S == 60


def test_message_builders():
    assert ping.challenge_message(V.NONCE, V.CHALLENGE_HEIGHT, V.CHALLENGE_ISSUED_AT) == \
        V.CHALLENGE_MESSAGE
    assert ping.binding_message(V.PEER_ID, V.SERVICE_PUBKEY, "testnet") == V.BINDING_MESSAGE
    answer = dict(nonce=V.NONCE, peer_id=V.PEER_ID, service_pubkey=V.SERVICE_PUBKEY,
                  binding_sig=V.BINDING_SIG, **V.ANSWER_INPUTS)
    assert ping.answer_message(answer) == V.ANSWER_MESSAGE


def test_sign_matches_csr():
    assert ping.sign(secret(V.MONITOR_SECRET), V.CHALLENGE_MESSAGE) == V.CHALLENGE_SIG
    assert ping.sign(secret(V.SERVICE_SECRET), V.BINDING_MESSAGE) == V.BINDING_SIG
    assert ping.sign(secret(V.SERVICE_SECRET), V.ANSWER_MESSAGE) == V.ANSWER_SIG
    sig = ping.sign(secret(V.SERVICE_SECRET), "anything")
    assert len(sig) == 130 and sig.startswith("0x")
    assert int(sig[66:], 16) <= N // 2


def test_verify():
    mpk = V.MONITOR_PUBKEY
    assert ping.verify(mpk, V.CHALLENGE_MESSAGE, V.CHALLENGE_SIG) is True
    assert ping.verify(from_hex(mpk), V.CHALLENGE_MESSAGE, V.CHALLENGE_SIG) is True
    assert ping.verify(mpk, V.CHALLENGE_MESSAGE, high_s(V.CHALLENGE_SIG)) is True  # S normalised
    assert ping.verify(mpk, V.CHALLENGE_MESSAGE + "x", V.CHALLENGE_SIG) is False
    assert ping.verify(V.SERVICE_PUBKEY, V.CHALLENGE_MESSAGE, V.CHALLENGE_SIG) is False
    for bad in ("", "0x", "0x12", V.CHALLENGE_SIG[2:], "0x" + "00" * 64, "0x" + "zz" * 64, None):
        assert ping.verify(mpk, V.CHALLENGE_MESSAGE, bad) is False
    assert ping.verify("0x02" + "00" * 32, V.CHALLENGE_MESSAGE, V.CHALLENGE_SIG) is False
    assert ping.verify("nonsense", V.CHALLENGE_MESSAGE, V.CHALLENGE_SIG) is False


def test_valid_nonce():
    assert ping.valid_nonce("0x" + "a" * 64)
    assert not ping.valid_nonce("0x" + "A" * 64)
    assert not ping.valid_nonce("0xab")
    assert not ping.valid_nonce("a" * 66)
    assert not ping.valid_nonce(None)


def test_make_challenge():
    ch = ping.make_challenge(secret(V.MONITOR_SECRET), height=V.CHALLENGE_HEIGHT,
                             issued_at=V.CHALLENGE_ISSUED_AT, nonce=from_hex(V.NONCE))
    assert ch == {"nonce": V.NONCE, "height": V.CHALLENGE_HEIGHT,
                  "issued_at": V.CHALLENGE_ISSUED_AT, "monitor_sig": V.CHALLENGE_SIG}
    assert list(ch) == ["nonce", "height", "issued_at", "monitor_sig"]
    assert ping.verify_challenge(ch, V.MONITOR_PUBKEY)
    assert not ping.verify_challenge(dict(ch, height=901), V.MONITOR_PUBKEY)
    assert not ping.verify_challenge({"nonce": "x"}, V.MONITOR_PUBKEY)
    r1 = ping.make_challenge(secret(V.MONITOR_SECRET), height=1, issued_at=2)
    r2 = ping.make_challenge(secret(V.MONITOR_SECRET), height=1, issued_at=2)
    assert ping.valid_nonce(r1["nonce"]) and r1["nonce"] != r2["nonce"]


def test_make_answer_matches_csr():
    ch = {"nonce": V.NONCE, "height": V.CHALLENGE_HEIGHT, "issued_at": V.CHALLENGE_ISSUED_AT,
          "monitor_sig": V.CHALLENGE_SIG}
    body = ping.make_answer(secret(V.SERVICE_SECRET), ch, peer_id=V.PEER_ID, **V.ANSWER_INPUTS)
    assert set(body) == {"answer", "sig"}
    a = body["answer"]
    assert list(a) == list(ping.ANSWER_FIELDS)
    assert a["service_pubkey"] == V.SERVICE_PUBKEY
    assert a["binding_sig"] == V.BINDING_SIG
    assert body["sig"] == V.ANSWER_SIG
    assert ping.verify(V.SERVICE_PUBKEY, ping.answer_message(a), body["sig"])


def good_body():
    ch = {"nonce": V.NONCE, "height": 1, "issued_at": 2, "monitor_sig": "0x"}
    return ping.make_answer(secret(V.SERVICE_SECRET), ch, peer_id=V.PEER_ID, **V.ANSWER_INPUTS)


def test_parse_answer():
    body = good_body()
    answer, sig = ping.parse_answer(body)
    assert answer == body["answer"] and sig == body["sig"]

    def bad(mutator):
        b = good_body()
        mutator(b)
        with pytest.raises(ValueError):
            ping.parse_answer(b)

    bad(lambda b: b["answer"].pop("ping_mode"))
    bad(lambda b: b["answer"].update(extra="x"))
    bad(lambda b: b["answer"].update(tip_number="1000"))
    bad(lambda b: b["answer"].update(tip_number=True))
    bad(lambda b: b["answer"].update(uptime_s=-1))
    bad(lambda b: b["answer"].update(peer_id=5))
    bad(lambda b: b.update(extra=1))
    bad(lambda b: b.pop("sig"))
    for junk in (None, [], "x", {"answer": "x", "sig": "0x"}):
        with pytest.raises(ValueError):
            ping.parse_answer(junk)


def test_parse_checkin():
    body = {"peer_id": V.PEER_ID, "service_pubkey": V.SERVICE_PUBKEY, "binding_sig": V.BINDING_SIG,
            "network": "testnet", "csr_version": "0.1.0"}
    assert ping.parse_checkin(body) == body
    assert ping.parse_checkin(dict(body, future_field=1)) == body    # extra fields ignored
    for k in body:
        b = dict(body)
        b.pop(k)
        with pytest.raises(ValueError):
            ping.parse_checkin(b)
        with pytest.raises(ValueError):
            ping.parse_checkin(dict(body, **{k: 7}))
    with pytest.raises(ValueError):
        ping.parse_checkin("nope")


def test_verify_binding():
    assert ping.verify_binding(V.PEER_ID, V.SERVICE_PUBKEY, "testnet", V.BINDING_SIG)
    assert not ping.verify_binding(V.PEER_ID, V.SERVICE_PUBKEY, "mainnet", V.BINDING_SIG)
    assert not ping.verify_binding("QmOther", V.SERVICE_PUBKEY, "testnet", V.BINDING_SIG)
    assert not ping.verify_binding(V.PEER_ID, "0x02zz", "testnet", V.BINDING_SIG)
