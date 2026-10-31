"""monitor-v3: Registry v3 cells, CSR-ATTEST-v2 attestations, csr-config-type, endpoints (D20 A, D21 A, D24 A)."""
import json
import os

from csrmon import csrchain

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
V = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "registry-v3.json")))
TYPE_HASH = "0x" + V["registry_type_hash"]


def test_attestation_v2_message():
    m = csrchain.attestation_message_v2(V["peer_id"], "0x" + V["service_pubkey"], 1, V["expiry_ms"],
                                        V["stake"], TYPE_HASH)
    assert m.hex() == V["attestation_message_v2"]


def test_sign_attestation_v2():
    att = csrchain.sign_attestation_v2(bytes.fromhex(V["monitor_secret"]), peer_id=V["peer_id"],
                                       service_pubkey="0x" + V["service_pubkey"], network="testnet",
                                       expiry_ms=V["expiry_ms"], stake=V["stake"], registry_type_hash=TYPE_HASH)
    assert att["version"] == 2
    assert att["signature"] == "0x" + V["attestation_signature"]
    assert att["stake"] == V["stake"] and att["registry_type_hash"] == TYPE_HASH
    assert att["network"] == "testnet" and att["network_id"] == 1


def test_parse_registry_v3():
    for key, endpoint in (("registry_v3_no_endpoint", ""), ("registry_v3_with_endpoint", V["endpoint"])):
        r = csrchain.parse_registry_v3(bytes.fromhex(V[key]))
        assert r["version"] == 3
        assert r["peer_id"] == V["peer_id"]
        assert r["service_pubkey"] == "0x" + V["service_pubkey"]
        assert r["payout_lock_hash"] == "0x" + "77" * 32
        assert r["network"] == 1
        assert r["stake"] == V["stake"]
        assert r["expiry_ms"] == V["expiry_ms"]
        assert r["attestation_sig"] == "0x" + V["attestation_signature"]
        assert r["endpoint"] == endpoint


def test_parse_registry_v3_refuses_other_data():
    data = bytearray(bytes.fromhex(V["registry_v3_no_endpoint"]))
    data[44] = 2
    for bad in (bytes(data), bytes.fromhex(V["registry_v3_no_endpoint"])[:100], b""):
        try:
            csrchain.parse_registry_v3(bad)
        except ValueError:
            continue
        raise AssertionError("must raise ValueError")


def test_verify_attestation_v2():
    r = csrchain.parse_registry_v3(bytes.fromhex(V["registry_v3_no_endpoint"]))
    pk = "0x" + V["monitor_pubkey"]
    assert csrchain.verify_registry_v3(r, pk, TYPE_HASH)
    assert not csrchain.verify_registry_v3(r, pk, "0x" + "4f" * 32)
    other = dict(r, stake="0x" + "5b" * 32 + ":3")
    assert not csrchain.verify_registry_v3(other, pk, TYPE_HASH)


def test_registry_type_hash_from_config():
    from csrmon import configcell
    h = configcell.registry_type_hash("0x" + "47" * 32, "data2", "0x" + "a9" * 32)
    assert h.startswith("0x") and len(h) == 66


def test_wiring_and_docs():
    cc = open(os.path.join(ROOT, "csrmon", "configcell.py")).read()
    assert "parse_registry_v3" in cc and "verify_registry_v3" in cc and "sign_attestation_v2" in cc
    assert "attest_max_lifetime" in cc or "8 * DAY_MS" in cc or "MAX_LIFETIME" in cc
    proto = open(os.path.join(ROOT, "docs", "PROTOCOL.md")).read()
    assert "CSR-ATTEST-v2" in proto and "csr-config-type" in proto and "endpoint" in proto
