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
