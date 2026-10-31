"""Fakes for monitor-v3 (Registry v3, CSR-ATTEST-v2, csr-config-type).

CONFIG_CODE, CONFIG_DEP_TX  placeholder code hash / dep tx of the csr-config-type script
CONFIG_LINES                config lines that enable csr-config-type in a test config
config_type(args)           the csr-config-type script of the config cell
registry_type(code, args)   the csr-registry type script for that config cell
registry_v3_data(...)       Registry v3 cell data with a CSR-ATTEST-v2 signature
"""
from csrmon import configcell, csrchain, molecule
from csrmon.hashing import to_hex

CONFIG_CODE = "0x" + "c7" * 32
CONFIG_DEP_TX = "0x" + "6d" * 32
CONFIG_LINES = [f'config_type_code_hash = "{CONFIG_CODE}"', f'config_type_dep_tx = "{CONFIG_DEP_TX}"']
NETWORKS = {0: "mainnet", 1: "testnet", 2: "devnet"}


def config_type(args):
    return configcell.config_type_script(args, CONFIG_CODE)


def registry_type(code, args):
    # Integration (Oct 2026): the registry's args are the config_id (CSR spec/registry.md §2).
    return {"code_hash": code, "hash_type": "data2", "args": args}


def registry_v3_data(signer, *, peer, service_pubkey, stake, expiry_ms, type_hash, network_id=1,
                     att_peer=None, endpoint="", payout="0x" + "77" * 32):
    att = csrchain.sign_attestation_v2(signer, peer_id=att_peer or peer, service_pubkey=service_pubkey,
                                       network=NETWORKS[network_id], expiry_ms=expiry_ms, stake=stake,
                                       registry_type_hash=type_hash)
    reg = {"peer_id": peer, "service_pubkey": service_pubkey, "payout_lock_hash": payout,
           "network": network_id, "stake": stake, "expiry_ms": expiry_ms,
           "attestation_sig": att["signature"], "endpoint": endpoint, "prekeys": "0x"}
    return to_hex(csrchain.encode_registry_v3(reg))


def type_hash_of(script):
    return molecule.script_hash(script)
