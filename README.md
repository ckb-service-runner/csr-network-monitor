# CSR Network Monitor (`csrmon`)

`csrmon` challenges every registered CKB Service Runner (CSR), checks that it sits beside a synced CKB full node, scores and ranks the runners, and publishes the results through a public REST API, a small web page and a weekly signed Merkle summary in an on-chain "stat cell". One process serves one network (`testnet` or `mainnet`) with its own database, key and stat cell.

The monitor is a **reputation source, not a proof**: it reports what it observed from its own vantage point.

Python ≥ 3.11, standard library only at runtime.

## What changed in v2 (CSR alignment)

v2 follows the CKB Service Runner (`psawyerberlin/ckb-service-runner`) as source of truth: CSR ping protocol v1 (secp256k1/SHA-256 text messages, `POST /v1/challenge` on port 8131, outbound `/v1/checkin` + `/v1/answer`), nodes discovered through the CKB node's `get_peers`, `p2p_verified` vs `challenge_only` checks, the CSR-compatible API (`/v1/network`, `/v1/nodes/{peer_id}`, plus `/v1/locations` with runner counts per 2° map cell), on-chain registry scanning, `POST /v1/attest` attestations and the monitor-owned config cell clock. One hostname per network. Ranking, epochs and the stat cell are unchanged. See [docs/PROTOCOL.md](docs/PROTOCOL.md).

The public page shows a world map of runner locations (dots for 2° × 2° areas, region level only; unknown locations appear only in the ranking table).

## What changed in v3 (contracts-v3)

The monitor reads **Registry v3** cells (one node ID, optional `endpoint`, 32- or 64-byte dual-lock args), signs **`CSR-ATTEST-v2`** attestations that name the stake and the registry type hash (reply gains `version`, `stake`, `registry_type_hash`), never issues attestations living longer than 8 days beyond the clock, keeps the clock of its **`csr-config-type`** config cell (new keys `config_type_code_hash`, `config_type_hash_type`, `config_type_dep_tx`, `config_type_dep_index`) and challenges registered runners at their `endpoint`. v2 registry cells are no longer accepted. See [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Quick start

```sh
python3 -m venv venv && venv/bin/pip install .
cp config/monitor-testnet.toml monitor.toml   # edit paths, public_url, config_type_args, csr_registry_code_hash
venv/bin/csrmon check-config --config monitor.toml
venv/bin/csrmon keygen --config monitor.toml
venv/bin/csrmon init-db --config monitor.toml
venv/bin/csrmon run --config monitor.toml
```

Commands: `check-config`, `keygen`, `show-key`, `init-db`, `run` (each needs `--config PATH`; exit code 2 on a config error).

## Configuration

The monitor checks that every registration is backed by a live Nervos DAO deposit (`min_stake_ckb`; the deposit owner's consent is checked by the registry contract), attests only runners with such a stake and publishes its state in `/v1/nodes/{peer_id}`.

See [config/monitor-testnet.toml](config/monitor-testnet.toml) (all keys, commented). Main groups: network and paths, probing (`probe_interval_s`, `sync_threshold`), registration discovery, geolocation CSVs, P2P helper, API limits, ranking gates and the stat cell (disabled by default).

## Tests

```sh
python3 -m venv .venv && .venv/bin/pip install pytest && .venv/bin/python -m pytest acceptance/
node --test acceptance/phase9_format.test.mjs
```

## Documentation

- [docs/INSTALL.md](docs/INSTALL.md) – installation, systemd, Caddy, forwarded topology
- [docs/PROTOCOL.md](docs/PROTOCOL.md) – wire contract for CSR implementers
- [docs/P2P_HELPER.md](docs/P2P_HELPER.md) – external P2P check helper
- [DECISIONS.md](DECISIONS.md) – design decisions

Licensed under the MIT license.
