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
- `CSR-NODE-IDENTITY-v1\n{peer_id}\n{service_pubkey}\n{network}\n{ts}` – signed by the node's P2P key (`p2p_sig`) **and** by the service key (`service_sig`); body of `POST /v1/identity`.
- `CSR-ATTEST-v1`: attestation digest = `ckb_blake2b("CSR-ATTEST-v1" ‖ molecule(AttestationBody{peer_id, service_pubkey, network, expiry_ms}))`.

## Routes

### `POST /v1/challenge` (on the CSR node, port 8131)

Inbound mode. The monitor sends `{"nonce","height","issued_at","monitor_sig"}` (exactly these fields) and receives `{"answer": {13 fields}, "sig"}` (`tip_number`, `uptime_s` are numbers, the rest strings). The node answers 400 (bad nonce / not fresh, `|now − issued_at| > 60 s` / `height` above its tip), 403 (bad monitor signature), 409 (nonce replay), 429 (rate limit 10/min/IP), 503 (node data unavailable).

The monitor marks a probe `fail` for reasons such as `bad_format`, `late`, `bad_nonce`, `bad_signature`, `peer_id_mismatch`, `wrong_block_hash`, `unknown_tip`, and transport reasons `timeout`, `unreachable`, `bad_status`, `no_response`, `no_answer`, `no_checkin`. A correct answer more than `sync_threshold` blocks behind is *answered* but not in sync.

### `POST /v1/checkin` and `POST /v1/answer` (on the monitor, outbound mode)

For nodes behind NAT. Check-in body: `{"peer_id","service_pubkey","binding_sig","network","csr_version"}`.

| Route | Status | Body | Meaning |
|---|---|---|---|
| checkin | 200 | `{"challenge": {...}}` | challenge issued |
| checkin | 400 | `bad_request`, `wrong_network` | malformed body / other network |
| checkin | 401 | `bad_signature` | binding signature invalid |
| checkin | 413 | `too_large` | body too large |
| checkin | 429 | `slot_done`, `challenge_open`, `rate_limited` | the slot already has an outcome / a challenge is open / too many requests |
| checkin | 503 | `monitor_paused`, `unavailable` | tip cross-check failed / not available |
| answer | 200 | `{"result":"ok"}` | accepted (CSR treats HTTP 200 as accepted) |
| answer | 400 | `bad_request` | malformed |
| answer | 409 | `unknown_nonce` | no open challenge for this nonce |
| answer | 413 | `too_large` | body too large |
| answer | 422 | `{"result":"fail","failure_reason":…}` | answer evaluated as failed |

A correct answer creates the runner (mode `outbound`).

### `POST /v1/identity` (on the monitor, node identity proof)

Proves that the runner controls the P2P key of the CKB node behind its `peer_id` (decision D6 A). The runner signs the message

```
CSR-NODE-IDENTITY-v1\n{peer_id}\n{service_pubkey}\n{network}\n{ts}
```

(`ts` = Unix seconds, decimal) with the node's P2P key and with its service key (ping signature: SHA-256 of the UTF-8 text, 64-byte compact ECDSA secp256k1) and posts exactly these seven keys:

```json
{"peer_id": "Qm…", "service_pubkey": "0x02…", "network": "testnet", "ts": 1792281600,
 "p2p_pubkey": "0x03…", "p2p_sig": "0x…", "service_sig": "0x…"}
```

The monitor checks the time (`|now − ts| ≤ 300 s`), both signatures and that `peer_id = base58(0x12 ‖ 0x20 ‖ SHA-256(p2p_pubkey))` (the libp2p peer ID CKB derives from its compressed secp256k1 key).

| Status | Body | Meaning |
|---|---|---|
| 200 | `{"ok": true}` | proof stored |
| 400 | `bad_request` | not exactly the seven keys, wrong types or keys that are not compressed secp256k1 keys |
| 400 | `wrong_network` | other network |
| 400 | `stale` | `ts` more than 300 s from the monitor's clock |
| 401 | `bad_signature` | `p2p_sig` or `service_sig` invalid |
| 403 | `peer_mismatch` | `peer_id` is not derived from `p2p_pubkey` |
| 413 | `too_large` | body too large |
| 429 | `rate_limited` | too many requests (same per-IP limit `rate_limit_per_min` as the GET routes) |

On success the runner of `service_pubkey` (created with mode `outbound` if unknown, its `peer_id` set to the proven one) stores `p2p_pubkey` and `identity_proven_at = now`, and its `identity_mismatch` flag is cleared. Every other active runner that claims the same `peer_id` gets the `identity_mismatch` flag (score 0, not ranked). Runners repeat the proof regularly (daily); a proof is valid for ranking for 7 days.

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
| 413 | `too_large` | body too large |
| 429 | `rate_limited` | too many requests |
| 503 | `chain_unavailable`, `unavailable` | config cell clock unreadable / attestations not configured |

### `GET /v1/network` and `GET /v1/nodes/{peer_id}`

Read by the CSR dashboard (see `spec/monitor-public-api.md`). `/v1/network` returns `nodes_total`, `nodes_reachable` (probed ok within `reachable_window_s`), `countries` and `updated_at`. `/v1/nodes/{peer_id}` returns the ranking data, `attestation` and a `stake` object `{"status": "deposited"|"withdrawn"|"invalid"|"duplicate"|"none", "capacity_ckb": int|null, "outpoint": string|null}`, plus the ranking data of a node with `check_type` (`p2p_verified` / `peer_connected` / `challenge_only`, see below); status 404 `not_ranked` for nodes that are unknown, still provisional or otherwise unranked. `GET /v1/monitor` returns the monitor public key, version, tip, `stat_cell_type_hash`, `csr_config_type_hash`, `csr_registry_code_hash` and `p2p_address` (the monitor node's public P2P multiaddr `/ip4/…/tcp/…/p2p/<node id>` from `p2p_public_address`, `null` when not set). The runner answer (`/v1/{network}/runners/{id}`) also carries `check_type`, `identity_proven_at` (Unix time or `null`) and `unranked_reason` (`null` when ranked, else `provisional`, `flagged` or `identity_unproven`).

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
- **Probe flag**: a probe is marked P2P-connected (`p2p_verified` column of the probe) when the answering `peer_id` is a node ID the monitor's CKB node is connected to (for discovery: the peer that was probed).
- **`check_type`**: `p2p_verified` when the last daily P2P check (below) is `ok` and at most 48 h old; else `peer_connected` when a successful probe of the last 24 h came from a connected peer; else `challenge_only`.

## Daily P2P check (decision D12 A)

The monitor publishes its own node's P2P address as `p2p_address` in `GET /v1/monitor`; runners ask their CKB node to connect to it (e.g. `add_node`). Once per `p2p_interval_s` (default one day) per active runner, at a random time inside the period, the monitor reads `get_peers` of its own node **once per run** and judges the runner's `peer_id`:

- `not_connected` – the peer is not in the list or has no usable `sync_state`;
- `behind` – `sync_state.best_known_header_number` (hex) is more than `sync_threshold` below the monitor's tip;
- `wrong_chain` – `best_known_header_hash` differs from the monitor's block hash at that height, or the number is more than `sync_threshold` above the tip;
- `ok` – otherwise (a peer up to `sync_threshold` ahead of the monitor is fine; its hash cannot be compared yet).

`ok` is recorded as `ok`, everything else as `fail` with the verdict as `reason`. If the node cannot be read, every due runner of that run is recorded as `error` and is not retried before the next period. Nothing runs while probing is paused (tip cross-check). The results feed F30 (`p2p_ok / p2p_total` of the last 30 days). The P2P handshake itself proves that the peer holds the private key behind its peer ID, so a connected peer with that ID is that node.

**Limitation:** the check proves that the runner's node follows the chain's headers and holds the peer key. It does not download full blocks, so it does not prove that the node stores or serves block bodies.

The external helper command (`p2p_check_cmd`, `p2p_check_timeout_s`) was never shipped and is removed; a config that still contains these keys is rejected with a message.

## Identity requirement and rollout

`require_identity_proof` (bool, default `false`): when `true`, a runner is only ranked if it has an identity proof (`POST /v1/identity`) younger than 7 days; others stay unranked with `unranked_reason = "identity_unproven"`. Rollout:

1. Deploy the runner side (`node-identity-runner`): it sends identity proofs and connects its node to `p2p_address`.
2. Deploy this monitor with `require_identity_proof = false` and set `p2p_public_address`. Proofs are stored, conflicting claims are flagged, the daily check feeds F30, nobody loses a rank for a missing proof.
3. Watch `identity_proven_at` of the ranked runners; when (nearly) all have proofs, set `require_identity_proof = true` and restart.

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
