"""v2 Phase 3 acceptance: CSR on-chain formats (csrmon/csrchain.py): attestations, the registry
cell (molecule) and the monitor config cell. Vectors come from CSR's own Rust code."""
import pytest

import csr_vectors as V
from csrmon import csrchain, crypto
from csrmon.hashing import ckb_blake2b, from_hex, to_hex


def test_network_ids():
    assert csrchain.NETWORK_IDS == {"mainnet": 0, "testnet": 1, "devnet": 2}


def test_attestation_body_layout():
    p = V.PEER_ID.encode()
    body = csrchain.attestation_body(V.PEER_ID, V.SERVICE_PUBKEY, 1, V.ATTESTATION_EXPIRY_MS)
    n = len(p)
    assert body[:4] == (20 + 4 + n + 33 + 1 + 8).to_bytes(4, "little")
    assert body[4:20] == b"".join(x.to_bytes(4, "little") for x in (20, 24 + n, 57 + n, 58 + n))
    assert body[20:24] == n.to_bytes(4, "little") and body[24:24 + n] == p
    assert body[24 + n:57 + n] == from_hex(V.SERVICE_PUBKEY)
    assert body[57 + n] == 1
    assert body[58 + n:] == V.ATTESTATION_EXPIRY_MS.to_bytes(8, "little")


def test_attestation_message_matches_csr():
    msg = csrchain.attestation_message(V.PEER_ID, V.SERVICE_PUBKEY, V.ATTESTATION_NETWORK_ID,
                                       V.ATTESTATION_EXPIRY_MS)
    assert to_hex(msg) == V.ATTESTATION_MESSAGE
    body = csrchain.attestation_body(V.PEER_ID, V.SERVICE_PUBKEY, 1, V.ATTESTATION_EXPIRY_MS)
    assert msg == ckb_blake2b(b"CSR-ATTEST-v1" + body)


def test_sign_attestation_file():
    att = csrchain.sign_attestation(from_hex(V.MONITOR_SECRET), peer_id=V.PEER_ID,
                                    service_pubkey=V.SERVICE_PUBKEY, network="testnet",
                                    expiry_ms=V.ATTESTATION_EXPIRY_MS)
    assert att == {"peer_id": V.PEER_ID, "service_pubkey": V.SERVICE_PUBKEY, "network": "testnet",
                   "network_id": 1, "expiry_ms": V.ATTESTATION_EXPIRY_MS,
                   "signature": V.ATTESTATION_SIG, "monitor_pubkey": V.MONITOR_PUBKEY}
    assert csrchain.verify_attestation(att, V.MONITOR_PUBKEY)
    assert not csrchain.verify_attestation(dict(att, expiry_ms=att["expiry_ms"] + 1), V.MONITOR_PUBKEY)
    assert not csrchain.verify_attestation(att, V.SERVICE_PUBKEY)
    assert not csrchain.verify_attestation({"peer_id": 1}, V.MONITOR_PUBKEY)
    with pytest.raises(ValueError):
        csrchain.sign_attestation(from_hex(V.MONITOR_SECRET), peer_id=V.PEER_ID,
                                  service_pubkey=V.SERVICE_PUBKEY, network="moon", expiry_ms=1)


def test_parse_registry_vector():
    reg = csrchain.parse_registry(from_hex(V.REGISTRY_DATA))
    assert reg["peer_id"] == V.PEER_ID
    assert reg["service_pubkey"] == V.SERVICE_PUBKEY
    assert reg["float_lock_hash"] == V.REGISTRY_FLOAT_LOCK_HASH
    assert reg["network"] == 1
    assert reg["prekeys"] == "0x"
    att = reg["attestation"]
    assert att == {"peer_id": V.PEER_ID, "service_pubkey": V.SERVICE_PUBKEY, "network_id": 1,
                   "expiry_ms": V.ATTESTATION_EXPIRY_MS, "signature": V.ATTESTATION_SIG}
    assert csrchain.verify_attestation(att, V.MONITOR_PUBKEY)


def test_encode_registry_roundtrip():
    reg = csrchain.parse_registry(from_hex(V.REGISTRY_DATA))
    assert to_hex(csrchain.encode_registry(reg)) == V.REGISTRY_DATA
    other = dict(reg, prekeys="0x0102", float_lock_hash="0x" + "11" * 32)
    assert csrchain.parse_registry(csrchain.encode_registry(other)) == other


@pytest.mark.parametrize("mutate", [
    lambda d: d[:-1],                                       # truncated
    lambda d: d + b"\x00",                                  # trailing byte
    lambda d: (len(d) + 4).to_bytes(4, "little") + d[4:],   # wrong total size
    lambda d: b"",
    lambda d: d[:8],
])
def test_parse_registry_rejects_bad_molecule(mutate):
    with pytest.raises(ValueError):
        csrchain.parse_registry(mutate(from_hex(V.REGISTRY_DATA)))


def test_parse_registry_rejects_wrong_field_count():
    # a table with 7 offsets instead of 6
    d = from_hex(V.REGISTRY_DATA)
    first = int.from_bytes(d[4:8], "little")
    offsets = [int.from_bytes(d[4 + 4 * i:8 + 4 * i], "little") for i in range(first // 4 - 1)]
    body = d[first:]
    new_offsets = [o + 4 for o in offsets] + [len(d) + 4]
    total = 4 + 4 * len(new_offsets) + len(body)
    bad = total.to_bytes(4, "little") + b"".join(o.to_bytes(4, "little") for o in new_offsets) + body
    with pytest.raises(ValueError):
        csrchain.parse_registry(bad)


def test_config_cell_data():
    pk = from_hex(V.MONITOR_PUBKEY)
    data = csrchain.config_cell_data(pk, 1792281600123)
    assert len(data) == 49
    assert data[:33] == pk and data[33:41] == (1792281600123).to_bytes(8, "little")
    assert data[41:] == b"\x00" * 8
    assert csrchain.parse_config_cell(data) == {"monitor_pubkey": V.MONITOR_PUBKEY,
                                                "clock_ms": 1792281600123}
    assert csrchain.parse_config_cell(data[:41])["clock_ms"] == 1792281600123
    with pytest.raises(ValueError):
        csrchain.parse_config_cell(data[:40])
