# CSR Network Monitor (`csrmon`)

`csrmon` challenges every registered CKB Service Runner (CSR), checks that it sits beside a synced CKB full node, scores and ranks the runners, and publishes the results through a public REST API, a small web page and a weekly signed Merkle summary in an on-chain "stat cell". One process serves one network (`testnet` or `mainnet`) with its own database, key and stat cell.

The monitor is a **reputation source, not a proof**: it reports what it observed from its own vantage point.

Python ≥ 3.11, standard library only at runtime.

## Quick start

```sh
python3 -m venv venv && venv/bin/pip install .
cp config/monitor-testnet.toml monitor.toml   # edit paths, public_url, registration_code_hash
venv/bin/csrmon check-config --config monitor.toml
venv/bin/csrmon keygen --config monitor.toml
venv/bin/csrmon init-db --config monitor.toml
venv/bin/csrmon run --config monitor.toml
```

Commands: `check-config`, `keygen`, `show-key`, `init-db`, `run` (each needs `--config PATH`; exit code 2 on a config error).

## Configuration

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
