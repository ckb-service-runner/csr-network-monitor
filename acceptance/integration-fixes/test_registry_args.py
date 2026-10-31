"""Integration fix (Oct 2026): the registry type script's args are the config_id (contracts v3).

Vector: the contracts-v3 testnet deployment of CSR (deployments/testnet.json, Oct 31 2026).
"""
from csrmon import configcell


def test_testnet_v3_registry_type_hash():
    assert configcell.registry_type_hash(
        "0xc047d4036a79f38535eb8560f17b79aea100f9e27c2f9267c9fa333d4ebd5067", "data2",
        "0x912124d6e825500f3ef8b5d91f213d637e4b23ddf9f44a8142ed9a5e70678bc2",
    ) == "0xcbde41dc5ccedda96c6ceaa441317817eb35630859a50f4c8b5fc4a2226173f0"
