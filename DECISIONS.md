# Decisions

- Phase 1: secp256k1 uses affine coordinates with `pow(x, -1, p)`; fast enough (<20 ms per operation).
- Phase 1: config validation of `node_rpc` uses urllib.parse; ports and paths are allowed, userinfo is not checked.
- Phase 3: GeoDB keeps IPv4 ranges in array('I'); a (runner, slot) conflict is detected via INSERT OR IGNORE. Country table maps TF to AN, UM to NA.

## Phase 4
- `RpcChain.block_at_time` reads genesis first (0 if later than ts), then binary-searches up to the tip.
- `get_cells` stops at the first empty page or a missing/empty cursor.
- Registry: a cell whose out_point cannot be parsed counts as invalid; opt-in changes count as "updated".

## Phase 5
- Push slot closing keeps a per-runner "next slot to close" mark; slots at or after the slot of an open challenge are not closed until it is answered or expires. Missed push slots are recorded with ts = slot start.
- Push responses are recorded with the check-in time as `ts`; a late (but still open) answer is recorded as `late`.
- `unknown_tip` also applies when the chain cannot return a hash for the runner's tip; a missing expected block hash gives `wrong_block_hash`.
- Transport errors in pull probes: socket timeouts → `timeout`, everything else → `unreachable`. Exceptions from a probe thread (e.g. local node RPC down) skip that probe instead of recording a miss.

## Phase 8
- Ranking and summary are computed together and cached per day for 30 s; the runner detail reuses the cached ranking (rank/score/asn_peers).
- Runner detail 404s `unknown_runner` for non-active runners; history likewise.
- Non-`/v1/` paths return a plain `404 not_found` JSON until Phase 9 adds the page.
- A check-in body larger than 16384 bytes is rejected with 413 (the server reads at most 16385 bytes and closes the connection).
- Non-200 prober replies are passed through as-is with their status.

## Phase 9
- Static files are served only for GET; `/` and `/static/<name>` bypass the rate limiter and `/v1/` check. Cache-Control: no-cache.
- Page "ranked" count uses `runner_count`; ASN diversity shown from `diversity_index`.
- Map is a 19-column CSS grid; tile intensity scales with the country's share of the max count.

## Phase 10
- `build_pending` builds epochs strictly in order starting from the lowest unbuilt one; `pending_epochs` is computed from stored epochs.
- Leaf country is upper-cased; anything not 2 ASCII letters becomes "??". Summaries are normalised through a JSON round trip before storing.

## Phase 11
- Create transaction: target capacity accounts for the Type ID script (32-byte args) when computing occupied capacity.
- `publish` raises `ValueError` for an unknown epoch; `stat_cell_type_*` meta is set only after `send_transaction` succeeds.

## Phase 12
- Daemon tasks run on a simple due-time schedule in one loop (0.5 s tick); each is wrapped in try/except. P2P checks run in a separate thread every 5 s.
- Epoch publishing walks all epochs without `stat_cell_tx` in order; a failure stops that pass and is retried next hour.
- `show-key` exits 1 if the key file is missing; `keygen` on a malformed key file exits 1.
- The wheel ships `csrmon/web/*` as package data; the Dockerfile only copies the package and runs it from there (no pip install).
- Docs: the DB-IP/GeoLite2 CSV column description is generic (`start_ip,end_ip,value…`); the testnet ACP dep group is left as a placeholder to look up.

## v2 (CSR alignment)

- Phase 1: imported the complete v1 code (without `acceptance/`) from `/srv/aiworker/projects/csr-network-monitor` at commit `4b075d2b6f13d688700d09e771a8db8c0938082f` via `git archive HEAD`. No other changes; the v1 acceptance tests run unchanged.

## Phase 4
- `parse_peers` accepts addresses as `{"address": ...}` dicts (CKB format) or plain strings; an `/ip4/` address must hold a valid IPv4 (likewise ip6), otherwise it is skipped and the next address is tried.
- `config_type_args` requires `0x` + 64 hex chars (or empty).
- `discovery_mark` with `ok=False` keeps the previous `last_ok`; `set_registrations` replaces rows in one transaction.

## v2 Phase 5: CsrProber
- Known runners that answer are upserted preserving `p2p_pubkey`, `reg_outpoint`, `p2p_port` and `ranking_opt_in`; an active runner keeps its mode and endpoint when it checks in or is re-probed.
- Failed discovery probes record nothing in `probes` (no runner exists); only `discovery_mark` is updated. Discovery probes run concurrently (≤ `probe_workers`).
- `probe_endpoint` reports `latency_ms=None` for connection failures and timeouts.
- Outbound slot `k` is closed when `now ≥ (k+1)·I + I/2`; `run_due` while paused marks the current slot as paused so its miss is recorded as `excluded`/`monitor_paused`.
- Stale open outbound challenges are kept until `run_due` expires them; a new check-in is only refused while one younger than `answer_deadline_s` exists.

## v2 Phase 7: on-chain duties
- `update_clock` raises `ConfigCellError` when the tip header is unavailable; the "last 24 h" ok-probe window for attestations is `[now-86400, now]`.
- Registry cells with a registry `network` or attestation `network_id` other than this monitor's count as invalid; duplicates of a valid peer are all stored (`registration_for` picks the latest expiry).

## Map Phase 1: snapped coordinates
- City CSV is snapped to 2°x2° cell centres while loading; only distinct cells (list of tuples) are kept, ranges refer to them by index in `array` objects (IPv4 `I` by address, IPv6 `Q` keyed by the upper 64 bits). Adjacent/overlapping ranges with the same cell are merged. Rows are assumed sorted; if not, ranges are sorted and re-merged after loading. Expected memory for the real file (3–4 M rows, heavily merged to well under 1 M ranges at ~12–20 bytes each) is well under 150 MB; raw coordinates, city and region names are never kept.
- `runners.loc_lat/loc_lon` hold the cell centre; they are set together with country, and cleared (NULL) when country is `??` or no cell is known. Probes get no location columns. `CsrProber._record` passes the cell to `record_probe` but does not add it to the returned `rec`.

## Map Phase 2: GET /v1/locations
- Grid: `geo.GRID_DEG = 2` (about 220 km north–south). Coarse enough to never pinpoint an operator's town and to merge neighbours into one larger dot, fine enough for 1 px/degree on phones. Only the cell centre is stored (`runners.loc_lat/loc_lon`, per runner, never per probe) and published; raw coordinates, cities and regions are never kept.
- `/v1/locations` counts the same active runners as `/v1/network`; a runner is located only if both cell columns are set and its country is not `None`, `""` or `??`. `/v1/network` is unchanged. Sorting is count desc, lat desc, lon asc so output is deterministic.

## Map Phase 3: world map on the public page
- `worldmap.js` is copied byte for byte from `acceptance/map/` and loaded as a classic script before the module; the page only sets `innerHTML` with its `svg()` output. Colours come from CSS variables (light/dark), so the shared script stays style-free.
- Dots are the 2° cells from `/v1/locations`, sized by runner count; a click on a dot shows its label in `#map-info` (works on touch, no hover needed). If `/v1/locations` fails the map is drawn without dots and a notice is shown; the rest of the page still loads.
- Runners with unknown location are never drawn: placing them anywhere would be invented data. They show only in the country list ("unknown N") and as "unknown" in the ranking table.

## Stake Phase 1: Registry v2, stake check
- `check_stake` treats a malformed live-cell answer (missing `output`/`capacity`) as an RPC-level error and lets the exception propagate; a missing `data` is treated as not a deposit.
- `min_stake_ckb` is an int with minimum 1 and default 10000.

## D-A7-1: stake = referenced Nervos DAO deposit
- The registry cell references an operator-owned DAO deposit (`stake` out point); the float cell is gone, tips go to `payout_lock_hash`. The contract only checks the deposit at creation, so the monitor checks it continuously: live, DAO type script, 8 zero data bytes (not a phase-1 withdrawal), capacity >= `min_stake_ckb` (default 10 000 CKB), and in the registry scan owner lock hash == first 32 bytes of the registry cell's lock args.
- Extra states beyond deposited/withdrawn: `invalid` (with reason: not found, not DAO, not a deposit, too small, wrong owner) and `duplicate` (a deposit named by several registry cells counts only for the oldest by block number, tx index, out point; the rest get reason `stake_in_use`).
- Only deposited stakes enter `registrations`; all candidates are kept in `registry_stakes` for the API. RPC errors abort the scan before anything is stored.
- `POST /v1/attest` checks the stake on every request (also for cached attestations) without an owner check, since the registry cell does not exist yet. The attestation does not commit to the stake: it stays valid for the cell format and the stake is enforced by the monitor's scan. A stake used by another peer's deposited registration gives `stake_in_use`.
- Scan result gains `no_stake` (candidates not deposited).

## D-A8-1: the runner owns its registry cell, the deposit owner consents by signature
- The runner pays for and owns its registry cell with its own wallet (dual-lock `args[0..32]` = runner lock hash). The DAO deposit stays in the operator's wallet, so the two locks normally differ.
- The deposit owner proves consent by signing `CSR-STAKE-CONSENT-v1|<network>|<stake out point>|<service pubkey>|<peer id>` (Neuron "Sign message", digest `blake2b-256("Nervos Message:" ‖ text)`). The `csr-registry` contract checks it on creation and whenever stake or owner changes (errors 21-23).
- `scan_registry` no longer passes `owner_lock_hash` to `check_stake`, so `wrong_owner` is no longer reported. The 64-byte lock args check stays. `stake.py` is unchanged (the parameter is optional and unused by the scan).
- The monitor keeps checking "still deposited", ">= min_stake_ckb" and "one deposit, one registration" (oldest wins). Registry format, attestation and API are unchanged.

## monitor-v3
Registry v3, `CSR-ATTEST-v2`, `csr-config-type`, endpoints (contracts-v3; D20 A, D21 A, D24 A, F-MON-014).
- **Codec** (`csrchain.py`): `attestation_message_v2`, `sign_attestation_v2`, `verify_attestation_v2` (for replies), `parse_registry_v3`, `encode_registry_v3` (used by tests and kept symmetric with the parser), `verify_registry_v3`. `parse_registry_v3` requires exactly 10 fields (no molecule "compatible" extra fields) and version 3; `attestation_sig` is a fixed 65-byte `Signature`, `endpoint` must be UTF-8. The v1/v2 helpers (`sign_attestation`, `parse_registry`, `encode_registry`) stay as library functions for their own vector tests, but nothing in the monitor uses them any more: v2 cells are not accepted and v1 attestations are not issued.
- **`registry_type_hash(code_hash, hash_type, config_type_args)`**: the third argument is the `args` of the `csr-registry` script, i.e. the config cell's *type hash* (the concept's registry script has `args: config type hash`). The name follows the task; computing the config type hash from the raw `config_type_args` inside it would need two more parameters. `registry_hash_of(config)` / `config_hash_of(config)` derive both from the config.
- **`config_type_hash(args, code_hash, hash_type="data2")`** and `config_type_script(...)` take the `csr-config-type` code hash; the Type ID variant is gone. Config cell duties (clock, scan, attest, `csr_config_type_hash`) need both `config_type_args` and `config_type_code_hash`; with only the args set they stay off and the daemon logs a warning. This is not a config error so that a config with only `config_type_args` still loads (`check-config` stays usable during the switch).
- **Clock update**: `config_type_dep_tx`/`config_type_dep_index` is added as a `code` cell dep after the sighash dep group; without `config_type_dep_tx` `update_clock` raises and the daemon does not run the clock task. The update also refuses a config cell whose type script is not the configured `csr-config-type`. Key and reserved bytes are copied, the clock is only written when the tip timestamp is newer (never lowered).
- **Lifetime cap**: `MAX_LIFETIME_MS = 8 days − 1 hour`; the hour is margin for the clock cell moving between signing and the runner's registration tx. `attest_validity_days` > 7 is a config error (new `_MAX` table in `config.py`), so with valid configs the cap is a safety net (`attest_expiry_ms`).
- **Attestation**: signs the requested (normalised) stake and `registry_hash_of(config)`; without `csr_registry_code_hash` the reply is `503 unavailable`. The attestation cache returns a cached reply only when it is a v2 reply for the same stake (the signature now names the stake; old v1 cache rows are ignored). Reply keys: the old ones plus `version`, `stake`, `registry_type_hash`. `GET /v1/monitor` gains `csr_registry_type_hash`.
- **Scan**: v3 cells only, lock args of 32 or 64 bytes, signature checked against the registry type hash, network must match. The registration row stores `endpoint` (new column, migrated with `ALTER TABLE`); `registration_for` is unchanged (no endpoint), the endpoint is read through `registered_endpoints()` / `registration_endpoint()`.
- **Endpoints (F-MON-014)**: `Discovery.registered()` lists registrations with an endpoint whose runner is not yet an active inbound runner at that endpoint (backoff as discovery, keyed by the endpoint string); the daemon's discovery loop probes them after the `get_peers` candidates. The answer must carry the registered peer ID and service key, then the runner becomes an inbound runner at that endpoint (also when it was outbound or found at another address before). The `mon-hardening` rule (not present in this repository, implemented here as `discovery.endpoint_ip`): `http`/`https`, no credentials, query, fragment or whitespace, every resolved address public (`is_global`, not multicast) unless `allow_insecure_endpoints`. Plain `http` is allowed: CSR serves the ping API on 8131 without TLS and all messages are signed. It is checked when the candidate is built and again before every probe of a runner whose endpoint is its registered one (`endpoint_refused`). Remaining risk: DNS may change between the check and urllib's own lookup (rebinding); accepted for a probe that only sends a signed challenge.
- **No redirects**: `prober._default_post` uses an opener whose redirect handler refuses every redirect, for all probes (a 3xx is `bad_status`). No existing behaviour depended on redirects.
- **API**: the raw endpoint is never returned; `has_endpoint` (existing) stays the only hint.
- **Test changes** (existing tests that asserted v1/v2 behaviour):
  - `test_v2_onchain.py`: config cell type is `csr-config-type` (`CONFIG_LINES` from the new `fakes_v3.py`); `test_config_type_helpers` uses the new signatures and checks `registry_type_hash`; `test_read_clock_and_update` expects the `csr-config-type` code dep; `registry_cell` builds Registry v3 cells; `test_attest` expects a `sign_attestation_v2` reply.
  - `test_stake_attest.py`: config with `CONFIG_LINES`, config cell under `csr-config-type`, `test_attest_with_live_deposit` expects a v2 reply.
  - `test_stake_scan.py`: `reg_cell` builds v3 cells; `test_invalid_cells` uses a 20-byte lock as the bad one (32 bytes are valid now), adds a valid 32-byte-lock cell and a v2 cell that must be invalid (counts 2 valid / 3 invalid); configs get `CONFIG_LINES`.
  - `test_v2_daemon.py`: v3 registry cell, `csr-config-type` keys in the config, `csr_config_type_hash` with the new signature, the attestation is checked with `verify_attestation_v2` and names the stake.
  - New: `acceptance/fakes_v3.py`, `acceptance/test_monitor_v3_wiring.py`.
