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

## ping-v1-1-monitor
- Check-in v1.1: `ts` + `checkin_sig` verified after the binding check and before the pause/slot logic. Replay memory is a dict keyed by (service key, ts), entries expire after 120 s, capped at 10000 (oldest dropped). A pair is remembered even if the check-in is then refused for a slot reason.
- Open challenges carry a `fresh` flag; `_expire_open` records `no_answer` only for fresh ones, unsigned ones expire with a debug log.
- `require_checkin_sig` (bool, default false). Plan: switch it on once the runners on the network report version >= the v1.1 release.
- Lag answer (empty hash, tip below height) is `ok`/`in_sync: false`; it is checked after the signature, binding and nonce checks.
- `csrprobe.reject_reason` maps 400 `{"error":"clock_skew"}` to `clock_skew`.
- `docs/PROTOCOL.md`: the `POST /v1/attest` table is replaced by a pointer to the runner repository's `spec/monitor-public-api.md`.
- Changed `acceptance/test_v2_csrprobe.py::test_unanswered_challenge_and_known_runner`: its check-in is now signed (`ts` + `checkin_sig`), because an unsigned check-in's expiry is no longer recorded as `no_answer`.
