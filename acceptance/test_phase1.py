"""Phase 1 acceptance: hashing, secp256k1, base58, key files, config."""
import os
import stat
import textwrap

import pytest

import csrmon
from csrmon import hashing, crypto, base58, keys, config


# ---------- hashing ----------

def test_version():
    assert csrmon.__version__ == "0.1.0"


def test_ckb_blake2b_empty_vector():
    assert hashing.ckb_blake2b(b"").hex() == (
        "44f4c69744d5f8c55d642062949dcae49bc4e7ef43d388c5a12f42b5633d163e")


def test_ckb_blake2b_len_and_blake160():
    h = hashing.ckb_blake2b(b"abc")
    assert isinstance(h, bytes) and len(h) == 32
    assert hashing.blake160(b"abc") == h[:20]


def test_hex_helpers():
    assert hashing.to_hex(b"\x01\xab") == "0x01ab"
    assert hashing.to_hex(b"") == "0x"
    assert hashing.from_hex("0x01AB") == b"\x01\xab"
    assert hashing.from_hex("01ab") == b"\x01\xab"
    assert hashing.from_hex("0x") == b""
    for bad in ("0x1", "0xzz", "xyz"):
        with pytest.raises(ValueError):
            hashing.from_hex(bad)


# ---------- secp256k1 ----------

def _secret(n):
    return n.to_bytes(32, "big")


def test_pubkey_vectors():
    assert crypto.pubkey_from_secret(_secret(1)).hex() == (
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    assert crypto.pubkey_from_secret(_secret(2)).hex() == (
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")
    assert crypto.pubkey_from_secret(_secret(3)).hex() == (
        "02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")


def test_invalid_secret_rejected():
    for bad in (_secret(0), crypto.N.to_bytes(32, "big"), b"\x01" * 31):
        with pytest.raises(ValueError):
            crypto.pubkey_from_secret(bad)


def test_generate_secret():
    a, b = crypto.generate_secret(), crypto.generate_secret()
    assert len(a) == 32 and a != b
    assert 0 < int.from_bytes(a, "big") < crypto.N
    assert len(crypto.pubkey_from_secret(a)) == 33


def test_sign_verify_recover_roundtrip():
    sk = crypto.generate_secret()
    pk = crypto.pubkey_from_secret(sk)
    msg = hashing.ckb_blake2b(b"hello")
    sig = crypto.sign(sk, msg)
    assert isinstance(sig, bytes) and len(sig) == 65
    assert sig[64] in (0, 1, 2, 3)
    assert crypto.verify(pk, msg, sig) is True
    assert crypto.recover(msg, sig) == pk


def test_sign_is_deterministic_and_low_s():
    sk = _secret(0xC0FFEE)
    msg = hashing.ckb_blake2b(b"deterministic")
    s1, s2 = crypto.sign(sk, msg), crypto.sign(sk, msg)
    assert s1 == s2
    s = int.from_bytes(s1[32:64], "big")
    assert 0 < s <= crypto.N // 2
    other = crypto.sign(sk, hashing.ckb_blake2b(b"other"))
    assert other != s1


def test_verify_rejects_tampering():
    sk = crypto.generate_secret()
    pk = crypto.pubkey_from_secret(sk)
    msg = hashing.ckb_blake2b(b"m")
    sig = crypto.sign(sk, msg)
    assert not crypto.verify(pk, hashing.ckb_blake2b(b"x"), sig)
    other_pk = crypto.pubkey_from_secret(crypto.generate_secret())
    assert not crypto.verify(other_pk, msg, sig)
    broken = bytearray(sig)
    broken[10] ^= 0x01
    assert not crypto.verify(pk, msg, bytes(broken))
    # high-s form of the same signature must be rejected
    s = int.from_bytes(sig[32:64], "big")
    high = sig[:32] + (crypto.N - s).to_bytes(32, "big") + bytes([sig[64] ^ 1])
    assert not crypto.verify(pk, msg, high)


def test_verify_never_raises_on_garbage():
    pk = crypto.pubkey_from_secret(_secret(5))
    msg = hashing.ckb_blake2b(b"m")
    assert crypto.verify(pk, msg, b"") is False
    assert crypto.verify(pk, msg, b"\x00" * 65) is False
    assert crypto.verify(b"\x02" + b"\x00" * 32, msg, crypto.sign(_secret(5), msg)) is False
    assert crypto.verify(pk, b"short", crypto.sign(_secret(5), msg)) is False


def test_sign_rejects_bad_message_length():
    with pytest.raises(ValueError):
        crypto.sign(_secret(7), b"\x00" * 31)


def test_recover_rejects_garbage():
    with pytest.raises(ValueError):
        crypto.recover(hashing.ckb_blake2b(b"m"), b"\x00" * 65)


# ---------- base58 ----------

def test_base58_vectors():
    assert base58.b58encode(b"") == ""
    assert base58.b58encode(b"\x00\x00\x01") == "112"
    assert base58.b58encode(b"hello world") == "StV1DL6CwTryKyV"
    assert base58.b58decode("StV1DL6CwTryKyV") == b"hello world"
    assert base58.b58decode("112") == b"\x00\x00\x01"
    with pytest.raises(ValueError):
        base58.b58decode("0OIl")


# ---------- key files ----------

def test_key_file_created_private_and_reloaded(tmp_path):
    path = tmp_path / "sub" / "monitor.key"
    sk = keys.load_or_create_secret(str(path))
    assert len(sk) == 32
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600
    assert keys.load_or_create_secret(str(path)) == sk
    text = path.read_text().strip()
    assert text == "0x" + sk.hex()


def test_key_file_too_open_is_refused(tmp_path):
    path = tmp_path / "monitor.key"
    keys.load_or_create_secret(str(path))
    os.chmod(path, 0o644)
    with pytest.raises(keys.KeyFileError):
        keys.load_or_create_secret(str(path))


def test_key_file_garbage_is_refused(tmp_path):
    path = tmp_path / "monitor.key"
    path.write_text("not a key\n")
    os.chmod(path, 0o600)
    with pytest.raises(keys.KeyFileError):
        keys.load_or_create_secret(str(path))


# ---------- config ----------

def _write(tmp_path, body):
    p = tmp_path / "monitor.toml"
    p.write_text(textwrap.dedent(body))
    return str(p)


MINIMAL = """
network = "testnet"
public_url = "https://monitor.example.org"
db_path = "/var/lib/csrmon/testnet.db"
key_path = "/var/lib/csrmon/testnet.key"
"""


def test_config_minimal_defaults(tmp_path):
    c = config.load_config(_write(tmp_path, MINIMAL))
    assert c.network == "testnet"
    assert c.public_url == "https://monitor.example.org"
    assert c.node_rpc == "http://127.0.0.1:8114"
    assert c.listen_host == "127.0.0.1"
    assert c.listen_port == 8480
    assert c.probe_interval_s == 600
    assert c.probe_jitter_s == 60
    assert c.probe_timeout_s == 5
    assert c.probe_workers == 32
    assert c.sync_threshold == 10
    assert c.second_tip_source == ""
    assert c.crosscheck_interval_s == 600
    assert c.aggregate_interval_s == 600
    assert c.allow_insecure_endpoints is False
    assert not hasattr(c, "p2p_check_cmd")
    assert c.p2p_public_address == "" and c.require_identity_proof is False
    assert c.p2p_interval_s == 86400
    assert c.rate_limit_per_min == 60
    assert c.trusted_proxies == ["127.0.0.1", "::1"]
    assert c.gate_min_days == 120
    assert c.gate_min_runners == 20
    assert c.gate_max_asn_share == 0.25
    assert c.gate_max_country_share == 0.5
    assert c.provisional_days == 7
    assert c.probe_retention_days == 90
    assert c.stat_cell_enabled is False
    assert c.salt_path == "/var/lib/csrmon/testnet.db.salt"


def test_config_overrides(tmp_path):
    c = config.load_config(_write(tmp_path, MINIMAL + """
node_rpc = "http://localhost:8124"
probe_interval_s = 300
allow_insecure_endpoints = true
trusted_proxies = ["10.0.0.1"]
gate_max_asn_share = 0.3
salt_path = "/tmp/x.salt"
"""))
    assert c.node_rpc == "http://localhost:8124"
    assert c.probe_interval_s == 300
    assert c.allow_insecure_endpoints is True
    assert c.trusted_proxies == ["10.0.0.1"]
    assert c.gate_max_asn_share == 0.3
    assert c.salt_path == "/tmp/x.salt"


def test_config_ipv6_localhost_rpc_allowed(tmp_path):
    c = config.load_config(_write(tmp_path, MINIMAL + 'node_rpc = "http://[::1]:8114"\n'))
    assert c.node_rpc == "http://[::1]:8114"


@pytest.mark.parametrize("extra", [
    'node_rpc = "http://192.168.1.5:8114"\n',
    'node_rpc = "https://testnet.ckb.dev"\n',
    'probe_interval_s = 0\n',
    'gate_min_runners = 0\n',
    'probe_interval_s = "600"\n',
    'unknown_key = 1\n',
    'allow_insecure_endpoints = "yes"\n',
])
def test_config_rejects_bad_values(tmp_path, extra):
    with pytest.raises(config.ConfigError):
        config.load_config(_write(tmp_path, MINIMAL + extra))


def test_config_rejects_bad_network(tmp_path):
    body = MINIMAL.replace('"testnet"', '"devnet"')
    with pytest.raises(config.ConfigError):
        config.load_config(_write(tmp_path, body))


@pytest.mark.parametrize("missing", ["network", "public_url", "db_path", "key_path"])
def test_config_requires_keys(tmp_path, missing):
    lines = [l for l in MINIMAL.strip().splitlines() if not l.startswith(missing + " ")]
    with pytest.raises(config.ConfigError):
        config.load_config(_write(tmp_path, "\n".join(lines) + "\n"))


def test_config_bad_toml(tmp_path):
    with pytest.raises(config.ConfigError):
        config.load_config(_write(tmp_path, "network = \n"))


def test_config_missing_file(tmp_path):
    with pytest.raises(config.ConfigError):
        config.load_config(str(tmp_path / "nope.toml"))
