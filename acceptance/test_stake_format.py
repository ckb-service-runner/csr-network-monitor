"""Stake phase 1: Registry v2 format (spec/registry.md v2 of ckb-service-runner), out points, config."""
import pytest

import csr_vectors as V
from csrmon import chain as chain_mod, config as config_mod, csrchain
from csrmon.hashing import from_hex, to_hex

REGISTRY_V2_DATA = V.REGISTRY_V2_DATA
STAKE = V.REGISTRY_STAKE


def test_parse_registry_v2_vector():
    reg = csrchain.parse_registry(from_hex(REGISTRY_V2_DATA))
    assert reg == {
        "peer_id": V.PEER_ID, "service_pubkey": V.SERVICE_PUBKEY, "payout_lock_hash": "0x" + "77" * 32,
        "network": 1,
        "attestation": {"peer_id": V.PEER_ID, "service_pubkey": V.SERVICE_PUBKEY, "network_id": 1,
                        "expiry_ms": V.ATTESTATION_EXPIRY_MS, "signature": V.ATTESTATION_SIG},
        "prekeys": "0x", "stake": STAKE}
    assert csrchain.verify_attestation(reg["attestation"], V.MONITOR_PUBKEY)


def test_encode_registry_v2_roundtrip():
    reg = csrchain.parse_registry(from_hex(REGISTRY_V2_DATA))
    assert to_hex(csrchain.encode_registry(reg)) == REGISTRY_V2_DATA
    other = dict(reg, prekeys="0x0102", payout_lock_hash="0x" + "11" * 32, stake="0x" + "ab" * 32 + ":4294967295")
    assert csrchain.parse_registry(csrchain.encode_registry(other)) == other
    raw = csrchain.encode_registry(dict(reg, stake="0x" + "01" * 32 + ":258"))
    assert raw[-36:] == bytes([1] * 32) + (258).to_bytes(4, "little")


def test_v1_registry_is_rejected():
    with pytest.raises(ValueError):
        csrchain.parse_registry(from_hex(V.REGISTRY_DATA))      # 6 fields, the float era


@pytest.mark.parametrize("mutate", [
    lambda d: d[:-1],
    lambda d: d + b"\x00",
    lambda d: (len(d) + 4).to_bytes(4, "little") + d[4:],
    lambda d: d[:-36] + d[-35:],                              # stake of 35 bytes, sizes inconsistent
    lambda d: b"",
])
def test_parse_registry_v2_rejects_bad_molecule(mutate):
    with pytest.raises(ValueError):
        csrchain.parse_registry(mutate(from_hex(REGISTRY_V2_DATA)))


def test_parse_registry_v2_rejects_short_stake():
    # a well-formed 7-field table whose last field has 35 bytes
    d = from_hex(REGISTRY_V2_DATA)[:-1]
    d = len(d).to_bytes(4, "little") + d[4:]
    with pytest.raises(ValueError):
        csrchain.parse_registry(d)


def test_parse_outpoint():
    assert csrchain.parse_outpoint("0x" + "ab" * 32 + ":0") == (bytes([0xab] * 32), 0)
    assert csrchain.parse_outpoint("0x" + "AB" * 32 + ":17") == (bytes([0xab] * 32), 17)
    assert csrchain.parse_outpoint("0x" + "00" * 32 + ":4294967295")[1] == 4294967295
    for bad in ["", "0x" + "ab" * 32, "0x" + "ab" * 31 + ":0", "ab" * 32 + ":0", "0x" + "ab" * 32 + ":-1",
                "0x" + "ab" * 32 + ":4294967296", "0x" + "ab" * 32 + ":01", "0x" + "zz" * 32 + ":0",
                "0x" + "ab" * 32 + ":0 ", None, 5]:
        with pytest.raises(ValueError):
            csrchain.parse_outpoint(bad)


def test_get_live_cell_rpc():
    calls = []

    class C(chain_mod.RpcChain):
        def call(self, method, params):
            calls.append((method, params))
            return {"cell": None, "status": "dead"}

    c = C("http://127.0.0.1:1")
    assert c.get_live_cell("0x" + "ab" * 32, 10) == {"cell": None, "status": "dead"}
    assert calls == [("get_live_cell", [{"tx_hash": "0x" + "ab" * 32, "index": "0xa"}, True])]


def test_min_stake_config(tmp_path):
    base = ['network = "testnet"', 'public_url = "https://m"', f'db_path = "{tmp_path}/t.db"',
            f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "a.toml").write_text("\n".join(base) + "\n")
    assert config_mod.load_config(str(tmp_path / "a.toml")).min_stake_ckb == 10000
    (tmp_path / "b.toml").write_text("\n".join(base + ["min_stake_ckb = 500"]) + "\n")
    assert config_mod.load_config(str(tmp_path / "b.toml")).min_stake_ckb == 500
    (tmp_path / "c.toml").write_text("\n".join(base + ["min_stake_ckb = 0"]) + "\n")
    with pytest.raises(config_mod.ConfigError):
        config_mod.load_config(str(tmp_path / "c.toml"))
