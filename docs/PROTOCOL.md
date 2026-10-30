# CSR wire protocol (monitor side)

**CSR (CKB Service Runner, `psawyerberlin/ckb-service-runner`) is the source of truth.** The monitor speaks the protocols defined there:

- `spec/ping-protocol.md` – ping protocol v1 (challenge, binding, answer, check-in)
- `spec/registry.md` – registry cell, attestation, config cell
- `spec/monitor-public-api.md` – `GET /v1/network`, `GET /v1/nodes/{peer_id}`

This file summarises what the monitor implements; on any difference the CSR specs win.

## Primitives

- **Ping signature**: message → `SHA-256(UTF-8)` → ECDSA secp256k1, 64-byte compact `r ‖ s`, as `0x` + 128 hex. Signers use RFC 6979 and low-S; verifiers normalise S (accept high-S).
- **Hash `ckb_blake2b`**: BLAKE2b-256 with personalization `ckb-default-hash`. `blake160` is its first 20 bytes. Used for attestations, runner ids and the stat cell.
- **Attestation / epoch signature**: 65 bytes `r ‖ s ‖ recid`, low-S, over a 32-byte digest.
- Hex is `"0x"` + lowercase; binary integers are little-endian; times are Unix seconds UTC.
- **runner_id** = `ckb_blake2b(service_pubkey)`; the `peer_id` (CKB node id, `Qm…`) is stored with the runner.

## Messages

Fields are joined with `\n`, no trailing newline, numbers in decimal.

- `CSR-PING-CHALLENGE-v1\n{nonce}\n{height}\n{issued_at}` – signed by the monitor.
- `CSR-BINDING-v1\n{peer_id}\n{service_pubkey}\n{network}` – signed by the P2P/node key (binding_sig); proves the service key belongs to the node id.
- `CSR-PING-ANSWER-v1\n` + the 13 answer fields in order: `nonce, peer_id, service_pubkey, binding_sig, network, csr_version, node_version, r2_state, tip_number, tip_hash, block_hash_at_height, uptime_s, ping_mode` – signed by the service key.
- `CSR-ATTEST-v1`: attestation digest = `ckb_blake2b("CSR-ATTEST-v1" ‖ molecule(AttestationBody{peer_id, service_pubkey, network, expiry_ms}))`.

## Routes

### `POST /v1/challenge` (on the CSR node, port 8131)

Inbound mode. The monitor sends `{"nonce","height","issued_at","monitor_sig"}` (exactly these fields) and receives `{"answer": {13 fields}, "sig"}` (`tip_number`, `uptime_s` are numbers, the rest strings). The node answers 400 (bad nonce / not fresh, `|now − issued_at| > 60 s` / `height` above its tip), 403 (bad monitor signature), 409 (nonce replay), 429 (rate limit 10/min/IP), 503 (node data unavailable).

The monitor marks a probe `fail` for reasons such as `bad_format`, `late`, `bad_nonce`, `bad_signature`, `peer_id_mismatch`, `wrong_block_hash`, `unknown_tip`, and transport reasons `timeout`, `unreachable`, `bad_status`, `no_response`, `no_answer`, `no_checkin`. A correct answer more than `sync_threshold` blocks behind is *answered* but not in sync.

**Tip challenge.** The challenge `height` is drawn from the last 100 blocks: `tip − randrange(1, 101)` (clamped at 0), `tip` being the monitor's tip. After the signature, binding, peer and `block_hash_at_height` checks, the monitor checks the answer's tip, with `mtip` the monitor's tip:

1. `tip_number < height` fails with `tip_below_height`.
2. `tip_number > mtip + sync_threshold` fails with `unknown_tip` (a tip the monitor's node does not know).
3. `mtip < tip_number <= mtip + sync_threshold` is ok with lag 0 (the monitor cannot check the hash yet).
4. Otherwise `tip_hash` must equal the monitor's block hash at `tip_number`. A mismatch fails with `unknown_tip`, unless `tip_number >= mtip − FORK_TOLERANCE_BLOCKS` (3): a different tip within 3 blocks of the monitor's tip is a recent fork, not a miss, and the probe is ok.

`lag = max(0, mtip − tip_number)`.

**Answer deadline.** Pull (inbound) probes must be answered within `probe_timeout_s` (default 5 s). Push (outbound) runners get `answer_deadline_s` (default 60 s) between the check-in reply and the answer (decision D8 B). The reason: push runners are typically behind home connections and the answer needs a full round trip (check-in, challenge, node work, answer) that a 5 s limit would often miss; a pull probe is a single request to a reachable endpoint. The deadline is not shortened: an answer after it fails with `late`, no answer at all with `no_answer`.

**`bad_binding` flag.** A probe that fails with `bad_binding` sets the runner's `bad_binding` flag (score 0, excluded from the ranking, bit 4 of the epoch leaf flags). The next good probe clears it.

### `POST /v1/checkin` and `POST /v1/answer` (on the monitor, outbound mode)

For nodes behind NAT. Check-in body: `{"peer_id","service_pubkey","binding_sig","network","csr_version"}`.

| Route | Status | Body | Meaning |
|---|---|---|---|
| checkin | 200 | `{"challenge": {...}}` | challenge issued |
| checkin | 400 | `bad_request`, `wrong_network` | malformed body / other network |
| checkin | 401 | `bad_signature` | binding signature invalid |
| checkin | 413 | `too_large` | body too large |
| checkin | 429 | `slot_done`, `challenge_open`, `rate_limited` | the slot already has an outcome / a challenge is open / too many requests (`rate_limit_post_per_min`, default 20 per client IP, counted separately from the GET limit `rate_limit_per_min` and checked before signatures or RPC calls; `Retry-After` is set) |
| checkin | 503 | `monitor_paused`, `unavailable` | tip cross-check failed / not available |
| answer | 200 | `{"result":"ok"}` | accepted (CSR treats HTTP 200 as accepted) |
| answer | 400 | `bad_request` | malformed |
| answer | 409 | `unknown_nonce` | no open challenge for this nonce |
| answer | 413 | `too_large` | body too large |
| answer | 422 | `{"result":"fail","failure_reason":…}` | answer evaluated as failed |

A correct answer creates the runner (mode `outbound`).

### `POST /v1/attest`

Body `{"peer_id","service_pubkey","binding_sig","network","stake"}` (`stake` = out point text `0x<64 hex>:<index>` of the Nervos DAO deposit); reply is CSR's attestation file `{"peer_id","service_pubkey","network","network_id","expiry_ms","signature","monitor_pubkey"}` (input of `csr register prepare`).

| Status | Body | Meaning |
|---|---|---|
| 200 | attestation | issued (or cached) |
| 400 | `bad_request`, `wrong_network` | malformed / other network |
| 401 | `bad_signature` | binding invalid |
| 403 | `not_eligible` | see policy below |
| 403 | `stake_invalid` (with `reason`) | the stake is not a deposited DAO cell (`spent`, `not_found`, `not_dao`, `not_deposit`, `too_small`) |
| 403 | `stake_in_use` | the deposit backs a registration of another peer |
| 403 | `stake_mismatch` | the peer or service key already has a registry cell, and the request does not name that cell's deposited stake. An operator who changes the deposit after a withdrawal removes the registry cell first (or updates it while the old attestation is still valid) |
| 413 | `too_large` | body too large |
| 429 | `rate_limited` | too many requests (`rate_limit_post_per_min`, shared by `/v1/checkin`, `/v1/answer` and `/v1/attest`) |
| 503 | `chain_unavailable`, `unavailable` | config cell clock unreadable / attestations not configured |

### `GET /v1/network` and `GET /v1/nodes/{peer_id}`

Read by the CSR dashboard (see `spec/monitor-public-api.md`). `/v1/network` returns `nodes_total`, `nodes_reachable` (probed ok within `reachable_window_s`), `countries` and `updated_at`. `/v1/nodes/{peer_id}` returns the ranking data, `attestation` and a `stake` object `{"status": "deposited"|"withdrawn"|"invalid"|"duplicate"|"none", "capacity_ckb": int|null, "outpoint": string|null}`, plus the ranking data of a node with `check_type` (`peer_connected` / `challenge_only`); it answers 200 for every known runner and every peer with a registry row (with `rank: null` and `provisional` for unranked nodes, and `check_type: "none"` for a peer without a runner) and 404 `unknown_node` only for an unknown peer. `GET /v1/monitor` returns the monitor public key, version, tip, `stat_cell_type_hash`, `csr_config_type_hash` and `csr_registry_code_hash`.

### `GET /v1/locations`

Map data for the public page and CSR dashboards. Counts the same active runners as `/v1/network`.

```json
{"locations": [{"lat": 53, "lon": 13, "count": 2}], "located": 6, "unlocated": 2, "grid_deg": 2, "updated_at": 1792324800}
```

- `locations`: one entry per grid cell with the number of located runners in it, sorted by `count` descending, then `lat` descending, then `lon` ascending. `lat` and `lon` are the integer cell centre in degrees.
- `located` / `unlocated`: runners with / without a known cell (unlocated runners have no coordinates or country `??`); they sum to `nodes_total` of `/v1/network`.
- `grid_deg`: the cell size in degrees (2).
- `updated_at`: Unix time of the reply.

Only snapped 2° cells are published: no exact coordinates, cities or region names are ever stored or exposed.

## Discovery

- **Inbound nodes** publish no address on chain. Every `discovery_interval_s` the monitor reads `get_peers` of its own CKB node (`node_id` and multiaddrs) and sends `POST http://<peer ip>:8131/v1/challenge` to peers that are not yet runners, with a back-off (`discovery_backoff_s`) for peers that did not answer. A correct answer creates a runner (mode `inbound`), challenged once per slot afterwards.
- **Outbound nodes** check in; a correct answer creates the runner (mode `outbound`).
- **`peer_connected` vs `challenge_only`** (`check_type`): a probe is `peer_connected` when the answering `peer_id` is a node ID the monitor's CKB node is connected to (for discovery: the peer that was probed). It only means "a peer of the monitor's node"; it does not prove that the node is a P2P full node. A node is reported as `peer_connected` if any successful probe of the last 24 h had a connected peer, else `challenge_only`. This value was called `p2p_verified` before; that name is kept free for the real P2P full-node check. (The probe column in the database is still named `p2p_verified`.)

## Slots and the grace rule

slot = `int(ts // probe_interval_s)`. At most one outcome is recorded per runner per slot. Inbound runners are challenged once per slot. Outbound runners must check in during the slot; a check-in in the first half of the next slot still counts for the previous slot (grace), after that the slot is closed as `fail` (`no_checkin`). Slots during which probing is paused are `excluded`, never misses. Slots before the monitor started or before the runner was first seen are not counted.

## Registry, config cell and attestations

- The monitor owns the **config cell** (Type ID; lock = the monitor key's secp256k1 sighash lock). Data = `monitor_pubkey (33) ‖ clock_ms (u64 LE) ‖ 8 reserved bytes`. Every `clock_update_interval_s` the monitor spends it into the same lock/type with `clock_ms` = timestamp of the chain tip; the fee is taken from the cell capacity.
- **Registry cell** (`csr-registry`, Registry v2): type script `{code_hash: csr_registry_code_hash, hash_type: "data2", args: config cell type hash}`; lock `csr-dual-lock` with 64-byte args `owner_lock_hash (32) ‖ runner_lock_hash (32)`. Data is a molecule table with 7 fields:

  | # | field | type |
  |--:|---|---|
  | 0 | `peer_id` | `Bytes` (UTF-8) |
  | 1 | `service_pubkey` | `Byte33` |
  | 2 | `payout_lock_hash` | `Byte32` (lock hash of the anyone-can-pay tip cell) |
  | 3 | `network` | `byte` (0 mainnet, 1 testnet, 2 devnet) |
  | 4 | `attestation` | `Attestation {peer_id, service_pubkey, network, expiry_ms, signature[65]}` |
  | 5 | `prekeys` | `Bytes` |
  | 6 | `stake` | `OutPoint` = `tx_hash (32) ‖ index (u32 LE)` |

  v1 cells (6 fields) are invalid. The monitor scans these cells every `probe_interval_s` and keeps those whose network matches, whose attestation was signed by this monitor and matches the cell, and whose stake is deposited.
- **Stake** (D-A7-1): the stake is a Nervos DAO deposit in the operator's wallet (D-A8-1: the registry owner may be any lock, CSR uses the runner's own wallet; the deposit owner consents with a signed message `CSR-STAKE-CONSENT-v1|<network>|<stake out point>|<service pubkey>|<peer id>`, digest `blake2b-256("Nervos Message:" ‖ text)`, which the `csr-registry` contract checks on creation and on every change of stake or owner, errors 21–23; the monitor therefore does not compare the owners). Out points are written `0x<64 hex>:<index decimal>`. It is **deposited** when `get_live_cell` says `live` and the cell has the DAO type script `{code_hash: 0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e, hash_type: type, args: 0x}`, data of exactly 8 zero bytes, capacity ≥ `min_stake_ckb` (default 10 000 CKB). States: `deposited`; `withdrawn` (the cell is dead); `invalid` (anything else, with a reason: `not_found`, `not_dao`, `not_deposit`, `too_small`); `duplicate` (**one deposit, one registration**: of several registry cells naming the same deposit only the oldest – lowest block number, tx index, out point – counts). Only registrations with a deposited stake are valid.
- **Attestation policy** (`POST /v1/attest`): the binding signature must verify, the network must be the monitor's, and the node must be an active runner with that `peer_id` and at least `attest_min_ok_24h` (default 1) successful probes in the last 24 h; otherwise `403 not_eligible`. The `stake` must be a deposited DAO cell of at least `min_stake_ckb` (`403 stake_invalid` with a `reason`) not used by another peer's registration (`403 stake_in_use`); it is re-checked on every request, also when the cached attestation is returned. Validity = config cell `clock_ms` + `attest_validity_days` (default 7 days). The same attestation is returned from a cache for `attest_cache_s` (default 3600 s).

## Ranking and stake

In registry mode (`csr_registry_code_hash` and `config_type_args` both set) only runners whose registry cell has stake status `deposited` and whose service key matches the cell are ranked. All other runners are listed by `GET /v1/{network}/runners` with `rank: null` and their `stake_status` (`deposited`, `withdrawn`, `invalid`, `duplicate` or `none`), are not counted in `runner_count` or `asn_peers`, and are left out of the epoch leaves. Leaving the monitor ("Join off") means having no registry cell: the stake status becomes `none` and the rank disappears. Without registry mode ranking is unchanged.

## Score

`score_v1` is **frozen**. Score = 100 × (0.45·A30 + 0.15·A365 + 0.15·S30 + 0.15·F30 + 0.10·T), with weights A30 0.45, A365 0.15, S30 0.15, F30 0.15, T 0.10 (sum 1). A30/A365 are the availability over 30/365 days, S30 the share of ok probes in sync, F30 the share of passed P2P checks, T the age (capped at 365 days). The peer-count term P (5 %) was dropped; its weight went to A30 (decisions D11 B, D18 A). Any change to the formula needs `score_v2` and a new formula byte in the epoch (byte 29). A runner with the flag `identity_mismatch` or `bad_binding` scores 0.

## Epoch data and leaves

Every Monday 00:00 UTC (epoch boundaries) the monitor builds a Merkle tree over all ranked runners, sorted by runner_id.

Leaf (47 bytes): `runner_id(32) ‖ score×100 u16 ‖ a30×10000 u16 ‖ a365×10000 u16 ‖ f30×10000 u16 ‖ country(2 ASCII, "??" unknown) ‖ asn u32 ‖ flags u8` (flags: 1 provisional, 2 identity mismatch, 4 bad binding).

Epoch data (159 bytes) stored as the stat cell data:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version = 1 |
| 1 | 4 | epoch number (from 1) |
| 5 | 8 | start block |
| 13 | 8 | end block |
| 21 | 4 | runner count |
| 25 | 2 | country count |
| 27 | 2 | ASN count |
| 29 | 1 | score formula (1 = `score_v1`) |
| 30 | 32 | Merkle root |
| 62 | 32 | hash of the previous epoch data (zeros for the first) |
| 94 | 65 | monitor signature over `ckb_blake2b("CSR/v1/epoch" ‖ data[0:94])` |

## Merkle rules

- `leaf_hash = ckb_blake2b(0x00 ‖ leaf)`; `node_hash = ckb_blake2b(0x01 ‖ left ‖ right)`.
- Levels are built left to right; an odd last node is promoted unchanged. An empty tree has root 32 zero bytes.
- A proof is a list of `{"side": "left"|"right", "hash": "0x…"}` siblings from the leaf upward; `side` is where the sibling sits.

## Verifying a runner against the stat cell

1. Get the leaf (and proof) from the API for the epoch, or rebuild the leaf from published values.
2. Read the stat cell by its type script hash (`stat_cell_type_hash` in `/v1/monitor`), take `output_data` (159 bytes), or the transaction of the epoch.
3. Verify the monitor signature with the monitor public key (`/v1/monitor`) over the first 94 bytes with the `CSR/v1/epoch` separator.
4. Fold the leaf hash with the proof and compare with the Merkle root at offset 30.

The monitor is a reputation source, not a proof: the data shows what the monitor observed.
