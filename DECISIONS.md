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

## fix-monitor-stake-ranking

Phase 1 – `/v1/nodes/{peer_id}` answers 200 for every known runner or registry row; 404 `unknown_node` otherwise.
- Changed tests: `acceptance/test_v2_api.py::test_nodes_endpoint` (new `provisional` key; provisional node now 200 with `rank: null`; unknown peer is 404 `unknown_node`) and `acceptance/test_v2_daemon.py` (provisional inbound node now 200 with `rank: null`, `provisional: true`).

Phase 2 – `scoring.stake_required(config)`; `rank_runners(..., require_stake=False)` adds `stake_status` to every item (stake row status if its service key matches case-insensitively, else `none`). In registry mode only `deposited` items are ranked; `runners.status` is never changed. `Api._ranking`, `network_summary`, `epochs.build_epoch` and `daemon` pass `require_stake=stake_required(config)`; `build_epoch` also omits non-deposited items from the leaves. `stake_status` added to `_RANK_KEYS`; documented in `docs/PROTOCOL.md`.
- Changed test: `acceptance/test_phase8.py::test_runners_paging` expects the new `stake_status` key in runner items.

Phase 3 – `Store.stakes_for(peer_id, service_pubkey)` (service key compared lower case; `_all` helper). `Attester.handle_attest` answers 403 `stake_mismatch` after `stake_in_use` and before the `last_issued` cache when the peer or service key has registry rows but none is the request's stake with status `deposited`. No rows: old rules. Documented in `docs/PROTOCOL.md`.
## mon-hardening
Phase 1 (F-SEC-005/006/007/012/013/014/017, F-MON-015/016).
- **D27 A**: signing uses libsecp256k1 through `coincurve` (`sign_recoverable(msg32, hasher=None)`), `crypto.BACKEND = "libsecp256k1"`. It is the first non-stdlib dependency, declared in `pyproject.toml` and the Dockerfile. Importing `csrmon.crypto` without it raises "csr-network-monitor needs the coincurve package (pip install coincurve)"; there is no pure-Python signing fallback. Signatures are byte-identical (RFC 6979, low s, same recid; checked against the old pure-Python vectors). Pure-Python `recover`, `verify` and `pubkey_from_secret` stay (they handle public data only).
- **Server**: handler `timeout = http_timeout_s` (default 10, min 1); `http_max_connections` (default 64, min 1) enforced with a semaphore in `process_request`: an extra connection gets `503` + `Connection: close` and is closed. INSTALL.md tells to set proxy timeouts too.
- **`netutil.fetch`/`fetch_status`**: opener without ProxyHandler, redirects refused (FetchError), at most `max_bytes` read, overall deadline = `timeout`. `fetch_status` returns `(status, body)` for non-2xx answers (probe). Probe answers max 16 KiB, node RPC max 4 MiB. `_default_post` now wraps `fetch_status`.
- **`public_ip`**: false for private, loopback, link-local, unspecified, multicast, reserved, 100.64/10, fc00::/7, fe80::/10 and IPv4-mapped forms of these. Note that `2001:db8::/32` (documentation) counts as private.
- **Private endpoints**: `Discovery.due` skips non-public peers; `Prober.probe_pull` and `CsrProber.probe_endpoint` record `fail/unreachable` without sending a request when the resolved IP is not public. Both are lifted by `allow_insecure_endpoints`. The check uses the resolved address before connecting; a DNS rebinding race between the check and the connection is not closed here.
- **Schedule**: `schedule.planned_time(secret, runner_id, slot, interval, jitter)` from `HMAC-SHA256(secret, "runner:slot")` (first 8 bytes → [0,1)), centre of the slot ± jitter, clamped. The secret is `HMAC(monitor secret, "csr-schedule")`. `P2PScheduler` takes `secret=` (the daemon passes the monitor key; a random one otherwise) and plans `start + 0.05P + u*0.85P`. The `_planned` maps are gone; the `rng` is no longer used for planning.
- **Headers**: static files get CSP `default-src 'self'; img-src 'self' data:; frame-ancestors 'none'` (the page needs nothing more), `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`; JSON answers get nosniff; same in `deploy/Caddyfile.example`.
- **POST limit**: `rate_limit_post_per_min` (default 20, min 1), own counter per client IP, checked in `Api.handle` for POST to `/v1/checkin|answer|attest` before routing. `CsrProber.handle_checkin` checks "challenge already open" before the chain RPC (and again before inserting), and caps open challenges at `MAX_OPEN_CHALLENGES = 10000` (503 `too_many_open_challenges`).
- **Privacy**: new database files are created 0600, existing ones chmod'ed to 0600 with a log line. `discovery` has column `ip_hash` = `sha256(salt ‖ ip)`; the salt (random, 32 bytes) lives in the `meta` table (`discovery_salt`), because `Store` does not know the salt file. Old `discovery` tables (plain IP column) are dropped on open: it is only a back-off cache. `discovery_get` returns the key as `ip_hash`. `runners.endpoint` still holds addresses (documented in INSTALL.md "Privacy").
- **Docker**: Dockerfile installs `coincurve` and documents `trusted_proxies`; INSTALL.md has a section on it (bridge gateway, or publish on host loopback only).
- **Existing tests changed** (they asserted behaviour this spec changes):
  - `acceptance/test_phase12.py::test_pyproject`: dependencies are now `["coincurve>=19"]`.
  - `acceptance/test_v2_store_discovery.py::test_discovery_table`: `discovery_get` returns `ip_hash`, not `ip`.
  - `acceptance/test_v2_store_discovery.py::test_discovery_due`: `allow_insecure_endpoints = true` (the IPv6 documentation address is not public).
  - `acceptance/test_v2_csrprobe.py`: `make()` sets `allow_insecure_endpoints = true` (loopback test nodes); the discovery check asserts a hashed key.
  - `acceptance/test_v2_daemon.py::test_end_to_end`: `allow_insecure_endpoints = true` (loopback CSR node).
- Environment note: no wheel of `coincurve` exists for Python 3.14, and its sdist build hook fails with cffi 2.x (it looks for `LICENSE` outside `licenses/`); the local `.venv` was built from a patched sdist. Python ≤ 3.13 installs a wheel normally.
## mon-scoring-probe
- **D13 A, tip challenge (F-MON-008):** `_new_challenge` draws the height from `tip - randrange(1, 101)` (clamped at 0). `evaluate_answer` checks `tip_hash` against the monitor's node: a tip above `mtip + sync_threshold` fails `unknown_tip`; a tip in `(mtip, mtip + sync_threshold]` is ok with lag 0; otherwise a hash mismatch fails `unknown_tip` unless `tip_number >= mtip - FORK_TOLERANCE_BLOCKS` (3, module constant in `csrprobe.py`). `tip_below_height` is kept.
- **D11 B, D18 A (F-MON-010):** the peer-count term P is gone from `score_v1`; weights are A30 0.45, A365 0.15, S30 0.15, F30 0.15, T 0.10. `score_v1` is frozen (comment in `scoring.py`, documented in `docs/PROTOCOL.md`): a change needs `score_v2` and a new formula byte in the epoch. `p` is removed from the runner metrics (also from the `metrics` object of `/v1/{network}/runners/{id}`); `median_peers` stays in `daily_stats` as information only.
- **D8 B (F-MON-009):** the 60 s answer deadline for push runners (`answer_deadline_s`) stays; pull probes keep `probe_timeout_s` (5 s). Documented in `docs/PROTOCOL.md` with the reason (home connections, push round trip).
- **bad_binding flag (F-MON-011):** `CsrProber._record` sets the flag on a `fail` with `bad_binding` and clears it on the next `ok` (only if set).
- **Label (F-MON-007):** `check_type` value `p2p_verified` is now `peer_connected` (the key `check_type` is unchanged); `CsrProber.p2p_verified()` is now `peer_connected()`; `_record` takes `peer_connected=`. The `probes.p2p_verified` column and `Store.record_probe(p2p_verified=)` keep their names (no migration; the name stays internal); `Store.peer_connected_since` reads it for the API. The name `p2p_verified` stays free for the real P2P full-node check.
- **Old registry path (F-MON-012):** removed `csrmon/registry.py`, the `sync` daemon task and the config keys `registration_code_hash`, `registration_hash_type`, `registration_args` (also from both example configs). A config that still has them fails to load with an error naming the keys to delete. `protocol.py` and `prober.py` are kept as they are: `protocol.runner_id`, `slot_of` and the transport helpers are used by `csrprobe.py`, and the old registration codec and `Prober` are still covered by the repository tests and the test fakes (`fakes.make_registration_cell`); removing them would mean deleting tests of behaviour this spec does not change. Nothing in the daemon calls them.
- **Test changes** (only where the spec changes the behaviour):
  - `test_phase1.py::test_config_minimal_defaults`: no longer asserts the three `registration_*` defaults.
  - `test_phase4.py`: removed the four `sync_registrations` tests and the `registry` import (old registry path).
  - `test_phase7.py`: weights, expected score and metric keys without `p`.
  - `test_phase8.py::test_runner_detail`: `metrics` keys without `p`.
  - `test_v2_api.py`: `check_type` is `peer_connected`.
  - `test_v2_csrprobe.py`: challenge height window is `tip-100..tip-1` (was `tip-19..tip-3`); the `rejected_400` case uses a node lagging 120 blocks (was 40), because the window is now 100 blocks.
- **For Patrick:** the runner dashboard shows `check_type`. The runner text for `peer_connected` needs a small runner change (part of `csr-docs`); until then it shows an unknown value.
## mon-ops-robustness
- Unknown epoch ids that are not ASCII digits give 404 `not_found`; digit ids that do not exist stay 404 `unknown_epoch`. `/v1/.../history` with `from`/`to` outside 0..now+1 day gives 400 `bad_request` (the older `bad_range` stays for inverted or over-long ranges).
- `/v1/network` and `/v1/locations` use a generic `_cached` helper (30 s, cleared by `invalidate()`); `nodes_reachable` comes from `Store.reachable_count`.
- `check-config` writes warnings to stderr and still prints `ok`; with `stat_cell_enabled` and no registry keys it prints a config error and exits 2 (a warning since D41).
- The example testnet config now sets `config_type_args` and `csr_registry_code_hash` (A8) uncommented.
- `TipCrossCheck.status` is `ok`/`diverged`/`unknown`/`off`; `Api` gets it through the new optional `cross` argument. A failing local node still pauses probing.
- Clock status: meta `clock_ms` is set by `read_clock` and `update_clock` (also when no update was needed); `config_cell_spare_shannons` is kept in meta and shown as `config_cell_spare_ckb`. The 30-day warning is logged whenever the config cell is read.
- `handle_attest` checks clock freshness only when it signs a new attestation; a cached attestation is still returned.
- Publishing state per epoch: columns `sent_block`, `published`, `superseded` (added by migration). `Store.get_epoch`/`list_epochs` keep their shape; `Store.epoch_states()` returns the new fields. `stat_cell_tx` keeps meaning "last sent hash" and is cleared when a transaction is to be sent again. If the tip cannot be read after sending, `sent_block` is null and `unknown` then counts as resend.
- `confirm` treats an RPC error from `get_transaction` as `wait`.
- `build_epoch` computes `late` as `now - end > 86400`. Existing stored epochs have no `built_at`/`late`.
- Ranking with each stake status was already covered by `test_stake_scan.py`; no new test.
- No existing repository test was changed.
## ping-v1-1-monitor
- Check-in v1.1: `ts` + `checkin_sig` verified after the binding check and before the pause/slot logic. Replay memory is a dict keyed by (service key, ts), entries expire after 120 s, capped at 10000 (oldest dropped). A pair is remembered even if the check-in is then refused for a slot reason.
- Open challenges carry a `fresh` flag; `_expire_open` records `no_answer` only for fresh ones, unsigned ones expire with a debug log.
- `require_checkin_sig` (bool, default false). Plan: switch it on once the runners on the network report version >= the v1.1 release.
- Lag answer (empty hash, tip below height) is `ok`/`in_sync: false`; it is checked after the signature, binding and nonce checks.
- `csrprobe.reject_reason` maps 400 `{"error":"clock_skew"}` to `clock_skew`.
- `docs/PROTOCOL.md`: the `POST /v1/attest` table is replaced by a pointer to the runner repository's `spec/monitor-public-api.md`.
- Changed `acceptance/test_v2_csrprobe.py::test_unanswered_challenge_and_known_runner`: its check-in is now signed (`ts` + `checkin_sig`), because an unsigned check-in's expiry is no longer recorded as `no_answer`.
## node-identity-monitor

- **D6 A – identity by the node's P2P key.** `POST /v1/identity` takes exactly `peer_id, service_pubkey, network, ts, p2p_pubkey, p2p_sig, service_sig`; the message `CSR-NODE-IDENTITY-v1\n{peer_id}\n{service_pubkey}\n{network}\n{ts}` uses the ping signature scheme (SHA-256, compact ECDSA) for both keys. Order of checks: shape (400 `bad_request`, which also covers keys that are not 33-byte compressed secp256k1 keys) → network → time ±300 s → both signatures (401) → derived peer ID (403 `peer_mismatch`). On success the runner gets `p2p_pubkey` and the new column `identity_proven_at`, its `identity_mismatch` flag is cleared, other active claimants of the peer ID get `identity_mismatch`. An unknown runner is created like a correct outbound answer creates one (mode `outbound`, no endpoint). If a known runner's stored `peer_id` differs from the proven one, it is updated to the proven one: a proof signed by both keys is stronger than a claim.
- `require_identity_proof` (default false) gates the ranking via `scoring.identity_ok` (proof ≤ 7 days old). `rank_runners`/`update_scores` take `require_identity` and `now` keyword arguments (`now` defaults to the end of `today`; epochs use the end of the epoch). Every ranking item has `unranked_reason` (`provisional`, `flagged`, `identity_unproven` or null); the runner answer shows it with `identity_proven_at` and `check_type`. The runner list items keep their exact key set (an existing test pins it).
- **POST rate limit.** `mon-hardening` (with its POST rate limit and `schedule.planned_time`) is not in this code base. `POST /v1/identity` therefore uses the existing per-IP limiter (`rate_limit_per_min`, so far only for GET); the other POST routes are unchanged. The P2P scheduler keeps its own plan time (start + 5 % + U(0, 85 %) of the period).
- **D12 A – daily check through the monitor's own node.** `p2p_public_address` (validated: a multiaddr ending in `/p2p/<id>`) is published as `p2p_address`. `P2PScheduler(store, chain, config, rng=None, clock=time.time, paused=None)` (`paused` is an optional callable; the daemon passes `lambda: prober.paused`, so nothing runs while the tip cross-check pauses probing) reads `get_peers` once per run. Verdicts of `evaluate_peer` other than `ok` are stored as `fail` with the verdict in the new `p2p_checks.reason` column; node errors are stored as `error` for all due runners (reason `node_error: <type>`), so they are not retried before the next period. Runners without a `peer_id` are skipped. The check no longer sets `identity_mismatch` (identity is now D6 A's job; the handshake authenticates the peer ID).
- `error` checks still count in `p2p_total` as before (an existing test pins this). A monitor node outage therefore lowers F30 for everyone due that day; possible follow-up: exclude `error` from the aggregate.
- **`check_type`.** `mon-scoring-probe` is not in this code base; the previous values here were `p2p_verified` (a probe from a connected peer in 24 h) and `challenge_only`. Now: `p2p_verified` = last daily check `ok` and ≤ 48 h old; else `peer_connected` = the old probe-based condition; else `challenge_only` (kept instead of `none` so existing API values stay).
- **Helper removed (F-MON-005).** `P2PChecker`, `run_p2p_check`, `p2p_check_cmd`, `p2p_check_timeout_s` and `docs/P2P_HELPER.md` are gone; a config with either key fails with "no longer supported" and a hint. The example configs carry `p2p_public_address` (commented) and `require_identity_proof = false` instead. `choose_heights` and `address_for` stay (pure helpers with their own tests).
- **Changed repository tests:**
  - `test_phase1.py::test_config_minimal_defaults`: asserts that `p2p_check_cmd` is gone and the new defaults instead of `p2p_check_cmd == ""`.
  - `test_phase6.py`: removed the helper script and the `P2PChecker`/`run_p2p_check` tests (`test_check_ok_and_request`, `test_check_failures`, `test_identity_mismatch_flag_set_and_cleared`); `test_scheduler` rewritten for the new scheduler (fake `get_peers`, `ok`/`fail` with reason, pause); added `test_removed_helper_keys_are_rejected`.
  - `test_phase12.py`: `docs/P2P_HELPER.md` dropped from the required files and its content check removed.
  - `test_v2_api.py::test_nodes_endpoint`: a node with only a P2P-connected probe now reports `peer_connected` (was `p2p_verified`); added a case where a daily check 47 h ago gives `p2p_verified`.
  - New `test_identity_ranking.py`: identity gate in the ranking, runner answer fields, proof for an unknown runner, rate limit of `POST /v1/identity`.
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
## mon-docs
- The old runner owner name was replaced everywhere by `ckb-service-runner`; the README links `https://github.com/ckb-service-runner/ckb-service-runner`.
- No `tools/shrink_city.py`: the city CSV is snapped while loading (`csrmon/geo.py`), so `INSTALL.md` gives the measured memory (about 500 MB peak plus swap on the reference host with the raw CSV) and mentions no tool.
- `PROTOCOL.md`: stat cell is a fixed binary layout of 159 bytes (not Molecule); the epoch list is documented as not paged (no code change); probe failure reasons copied from `csrprobe.py`; the plain binding is not claimed to be signed by the P2P key, the identity proof is `CSR-NODE-IDENTITY-v1`.
- The first transfer to a runner wallet is not stated here; the README refers to the runner README.

## Mainnet dashboard release (D29–D39, 31 Oct 2026)

Full list in the runner repository, `docs/decisions.md`. For the monitor:
- **D29**: ranking never depends on the stake, also in registry mode; `stake_status` stays in every item and the
  epoch leaves get a `FLAG_STAKED` bit (8) for deposited registrations. Supersedes "Phase 2" of
  fix-monitor-stake-ranking (stake-only ranking). The attestation still requires a deposited stake.
- **D30**: `require_identity_proof` stays the way to require the node identity for ranking.
- **D33/D34**: a second, mainnet instance (`csr-network-monitor@mainnet`) on pswsl with its own key; its URL
  and public key ship in the runner's `config/networks/mainnet.toml`.
- **D36**: Phase 2 gate defaults `gate_min_days = 120`, `gate_min_runners = 20`; diversity limits unchanged.

## mon-rank-without-stake

- `scoring.unranked_reason` no longer returns `stake`; `rank_runners` keeps its `require_stake` parameter for
  callers but it no longer changes the rank. `stake_required(config)` still tells whether registry mode is on.
- `epochs.FLAG_STAKED = 8`, set when the item's `stake_status` is `deposited`; every ranked runner is in the
  leaves again (leaf layout unchanged). The epoch `runner_count` counts every ranked runner.
- Gate defaults 120 days / 20 runners (config defaults and both example configs).
- Changed tests: the three stake-ranking tests in `acceptance/aiworker-fix-monitor-stake-ranking/test_fix_stake_ranking.py`
  now check the D29 rule; `test_phase1.py::test_config_minimal_defaults` (120/20); `test_phase7.py::test_gate_not_met`
  (progress 1/20). New: `acceptance/aiworker-mon-rank-without-stake/test_rank_without_stake.py`.

## D40 – one hostname for both networks (31 Oct 2026)

- The monitors are reached at one hostname with a path per network (`/testnet/`, `/mainnet/`), e.g.
  `https://csr-monitor.chainsolution.net/testnet`. Still one process per network (8480, 8481). Caddy strips the prefix
  (`handle_path`); the runner keeps the path of its monitor URL (`{url}/v1/...`).
- The web page uses relative paths (`static/…`, `v1/…`) so it works under a prefix and at the root. Changed tests:
  `test_phase9.py` and `map/test_map_page.py` accept relative paths. New: `acceptance/aiworker-monitor-path-prefix/`.
- DNS "only" (no CDN proxy): the monitor must see the runners' real IPs for country and ASN.

## D41 – stat cell without the registry (31 Oct 2026)

- The weekly ranking may be published on chain (stat cell) by a monitor without registry keys, e.g. on mainnet before
  1.x. The `check-config` error "stat_cell_enabled needs csr_registry_code_hash and config_type_args" (mon-ops-robustness)
  dated from the stake-only ranking; since D29 the leaves hold every ranked runner and mark staked ones with
  `FLAG_STAKED`, so it is now a warning ("no epoch leaf carries FLAG_STAKED"). The stat cell's own keys stay required.
  The daemon never enforced the old rule. New: `acceptance/aiworker-stat-cell-without-registry/`.

## D42 – GitHub links in the page footer (1 Nov 2026)

- The page has a footer linking to the runner repo ("Run a CSR node") and to this repo ("Monitor source on GitHub").
- The no-external-URL rule stays: the page loads nothing from outside. Plain `<a href>` links to
  `https://github.com/ckb-service-runner/<repo>` are the only exception, since following a link loads nothing into the
  page. Changed tests: `test_phase9.py` and `map/test_map_page.py`.
