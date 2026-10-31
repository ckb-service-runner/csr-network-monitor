# CSR wire protocol (monitor side)

**CSR (CKB Service Runner, `ckb-service-runner/ckb-service-runner`) is the source of truth.** The monitor speaks the protocols defined there:

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
- `CSR-BINDING-v1\n{peer_id}\n{service_pubkey}\n{network}` – the plain binding `binding_sig`, checked against the service key and the peer id. It is *not* signed by the P2P key; the identity proof `CSR-NODE-IDENTITY-v1` is what ties the service key to the node's P2P identity.
- `CSR-PING-ANSWER-v1\n` + the 13 answer fields in order: `nonce, peer_id, service_pubkey, binding_sig, network, csr_version, node_version, r2_state, tip_number, tip_hash, block_hash_at_height, uptime_s, ping_mode` – signed by the service key.
- `CSR-NODE-IDENTITY-v1\n{peer_id}\n{service_pubkey}\n{network}\n{ts}` – signed by the node's P2P key (`p2p_sig`) **and** by the service key (`service_sig`); body of `POST /v1/identity`.
- `CSR-ATTEST-v2` (monitor-v3, D21 A): attestation digest = `ckb_blake2b("CSR-ATTEST-v2" ‖ AttestationBodyV2)` with
  `AttestationBodyV2 = table { peer_id: Bytes, service_pubkey: Byte33, network: byte, expiry_ms: Uint64, stake: OutPoint, registry_type_hash: Byte32 }`.
  The signature (65 bytes `r ‖ s ‖ recid`) thus names the stake out point and the type hash of the `csr-registry` script it is valid for. The older `CSR-ATTEST-v1` (body without `stake` and `registry_type_hash`) is no longer issued or accepted.

## Routes

### `POST /v1/challenge` (on the CSR node, port 8131)

Inbound mode. The monitor sends `{"nonce","height","issued_at","monitor_sig"}` (exactly these fields) and receives `{"answer": {13 fields}, "sig"}` (`tip_number`, `uptime_s` are numbers, the rest strings). The node answers 400 (bad nonce / not fresh, `|now − issued_at| > 60 s` / `height` above its tip), 403 (bad monitor signature), 409 (nonce replay), 429 (rate limit 10/min/IP), 503 (node data unavailable).

The monitor marks a probe `fail` with one of these reasons: `bad_format`, `late`, `wrong_network`, `bad_nonce`, `bad_signature`, `bad_binding`, `peer_id_mismatch`, `wrong_block_hash`, `unknown_tip`, `tip_below_height`, `pubkey_changed`; from the HTTP status of the node `clock_skew` (400 with `{"error": "clock_skew"}`), `rejected_400` (other 400s), `bad_monitor_key` (403), `replay` (409), `rate_limited` (429), `node_unavailable` (503), `bad_status` (other); transport reasons `timeout`, `unreachable`; and slot reasons `no_answer`, `no_checkin`. A correct answer more than `sync_threshold` blocks behind is *answered* but not in sync. An answer with an empty `block_hash_at_height` and a `tip_number` below the challenge height is a reachable, not-in-sync probe (`ok`, `in_sync: false`, lag from the tips); an empty hash with `tip_number >= height` is `wrong_block_hash`.

**Tip challenge.** The challenge `height` is drawn from the last 100 blocks: `tip − randrange(1, 101)` (clamped at 0), `tip` being the monitor's tip. After the signature, binding, peer and `block_hash_at_height` checks, the monitor checks the answer's tip, with `mtip` the monitor's tip:

1. `tip_number < height` fails with `tip_below_height`.
2. `tip_number > mtip + sync_threshold` fails with `unknown_tip` (a tip the monitor's node does not know).
3. `mtip < tip_number <= mtip + sync_threshold` is ok with lag 0 (the monitor cannot check the hash yet).
4. Otherwise `tip_hash` must equal the monitor's block hash at `tip_number`. A mismatch fails with `unknown_tip`, unless `tip_number >= mtip − FORK_TOLERANCE_BLOCKS` (3): a different tip within 3 blocks of the monitor's tip is a recent fork, not a miss, and the probe is ok.

`lag = max(0, mtip − tip_number)`.

**Answer deadline.** Pull (inbound) probes must be answered within `probe_timeout_s` (default 5 s). Push (outbound) runners get `answer_deadline_s` (default 60 s) between the check-in reply and the answer (decision D8 B). The reason: push runners are typically behind home connections and the answer needs a full round trip (check-in, challenge, node work, answer) that a 5 s limit would often miss; a pull probe is a single request to a reachable endpoint. The deadline is not shortened: an answer after it fails with `late`, no answer at all with `no_answer`.

**`bad_binding` flag.** A probe that fails with `bad_binding` sets the runner's `bad_binding` flag (score 0, excluded from the ranking, bit 4 of the epoch leaf flags). The next good probe clears it.

### `POST /v1/checkin` and `POST /v1/answer` (on the monitor, outbound mode)

For nodes behind NAT. Check-in body: `{"peer_id","service_pubkey","binding_sig","network","csr_version"}`, in v1.1 plus `ts` (non-negative integer, seconds) and `checkin_sig` (string). `checkin_sig` is the service key's signature of `CSR-CHECKIN-v1\n{peer_id}\n{service_pubkey}\n{network}\n{ts}`. Both fields must be present or both absent (else 400 `bad_request`).

A check-in with `ts` is *fresh* if `|now − ts| <= 60 s` (else 400 `stale_checkin`), the signature is valid (else 401 `bad_signature`) and the pair (service key, `ts`) was not seen in the last 2 minutes (else 400 `replay`; the memory is bounded). Only a fresh check-in whose challenge expires unanswered is recorded as `no_answer`. An unsigned (v1) check-in still gets a challenge during the transition, but its expiry is not recorded. With config `require_checkin_sig` (default false) unsigned check-ins are refused with 400 `checkin_sig_required`.

| Route | Status | Body | Meaning |
|---|---|---|---|
| checkin | 200 | `{"challenge": {...}}` | challenge issued |
| checkin | 400 | `bad_request`, `wrong_network`, `stale_checkin`, `replay`, `checkin_sig_required` | malformed body / other network / `ts` outside ±60 s / (key, `ts`) seen before / unsigned check-in refused |
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

Body `{"peer_id","service_pubkey","binding_sig","network","stake"}` (`stake` = out point text `0x<64 hex>:<index>` of the Nervos DAO deposit); reply is CSR's attestation file `{"version": 2, "peer_id","service_pubkey","network","network_id","expiry_ms","stake","registry_type_hash","signature","monitor_pubkey"}` (input of `csr register prepare`): `stake` is the requested out point (normalised to lowercase), `registry_type_hash` the type hash of this monitor's `csr-registry` script (also in `GET /v1/monitor` as `csr_registry_type_hash`), `signature` the `CSR-ATTEST-v2` signature (`0x` + 130 hex).

Statuses and error codes are defined once, in `spec/monitor-public-api.md` of the runner repository; this document keeps no table of its own for this route. Reminder of the codes added by the 2026-10 audit fixes: 403 `stake_mismatch` (the peer or service key already has a registry cell and the request does not name that cell's deposited stake; an operator who changes the deposit after a withdrawal removes the registry cell first), 429 `rate_limited` (`rate_limit_post_per_min`) and 503 `clock_stale` (the config cell clock is older than `attest_max_clock_age_s`). The eligibility policy is described under "Registry, config cell and attestations" below.

### `GET /v1/network` and `GET /v1/nodes/{peer_id}`

Read by the CSR dashboard (see `spec/monitor-public-api.md`). `/v1/network` returns `nodes_total`, `nodes_reachable` (probed ok within `reachable_window_s`), `countries` and `updated_at`. `/v1/nodes/{peer_id}` returns the ranking data, `score` (score_v1, 0–100) with its terms `metrics` `{a30, s30, f30, t, age_days}` (both `null` for a peer without a runner), `location` `{lat, lon}` (the node's 2° map cell, the one `/v1/locations` counts it in; `null` when not located), `attestation` and a `stake` object `{"status": "deposited"|"withdrawn"|"invalid"|"duplicate"|"none", "capacity_ckb": int|null, "outpoint": string|null}`, plus the ranking data of a node with `check_type` (`p2p_verified` / `peer_connected` / `challenge_only`, see below); it answers 200 for every known runner and every peer with a registry row (with `rank: null` and `provisional` for unranked nodes, and `check_type: "none"` for a peer without a runner) and 404 `unknown_node` only for an unknown peer. `GET /v1/monitor` returns the monitor public key, version, tip, `stat_cell_type_hash`, `csr_config_type_hash`, `csr_registry_type_hash` and `csr_registry_code_hash`, plus `registry_last_scan_at` (unix seconds or null), `clock_ms`, `clock_age_s`, `config_cell_spare_ckb` (or null) and `crosscheck` (`ok`, `diverged`, `unknown`, `off`) and `p2p_address` (the monitor node's public P2P multiaddr `/ip4/…/tcp/…/p2p/<node id>` from `p2p_public_address`, `null` when not set). Unexpected errors answer `500 {"error":"internal"}`; `/v1/network` and `/v1/locations` are cached for 30 s. The runner answer (`/v1/{network}/runners/{id}`) also carries `check_type`, `identity_proven_at` (Unix time or `null`) and `unranked_reason` (`null` when ranked, else `provisional`, `flagged` or `identity_unproven`; `stake` is no longer given since D29).

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

A runner whose `peer_id` is the monitor's own node (`local_node_info`) never appears in that node's `get_peers`; it is judged `ok` when it proved that node's P2P key within the proof lifetime (7 days, `POST /v1/identity`), and like any other runner otherwise.

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

- The monitor owns the **config cell**: type script **`csr-config-type`** `{code_hash: config_type_code_hash, hash_type: config_type_hash_type (default data2), args: config_type_args}` (monitor-v3; before it was a Type ID script), lock = the monitor key's secp256k1 sighash lock. Data = `monitor_pubkey (33) ‖ clock_ms (u64 LE) ‖ 8 reserved bytes`. Every `clock_update_interval_s` the monitor spends it into the same lock/type with `clock_ms` = timestamp of the chain tip; the fee is taken from the cell capacity. The transaction has the sighash dep group and the `csr-config-type` code cell (`config_type_dep_tx`/`config_type_dep_index`, dep type `code`) as cell deps. **The clock only moves forward and the key never changes**: the monitor skips the update when the tip timestamp is not newer than `clock_ms` and copies the key and the reserved bytes unchanged; the contract refuses anything else anyway.
- **Registry cell** (`csr-registry`, **Registry v3**): type script `{code_hash: csr_registry_code_hash, hash_type: csr_registry_hash_type (default data2), args: config_id}` (the config cell's `config_type_args`, CSR `spec/registry.md` §2); its type hash is the **registry type hash** that the attestation names. Lock `csr-dual-lock` with 32- or 64-byte args. Data is a molecule table with 10 fields:

  | # | field | type |
  |--:|---|---|
  | 0 | `version` | `byte`, always 3 |
  | 1 | `peer_id` | `Bytes` (UTF-8, one node ID) |
  | 2 | `service_pubkey` | `Byte33` |
  | 3 | `payout_lock_hash` | `Byte32` (lock hash of the anyone-can-pay tip cell) |
  | 4 | `network` | `byte` (0 mainnet, 1 testnet, 2 devnet) |
  | 5 | `stake` | `OutPoint` = `tx_hash (32) ‖ index (u32 LE)` |
  | 6 | `expiry_ms` | `Uint64` |
  | 7 | `attestation_sig` | `Signature` (65 bytes, `CSR-ATTEST-v2` over fields 1, 2, 4, 6, 5 and the registry type hash) |
  | 8 | `endpoint` | `Bytes` (UTF-8 URL, empty = none) |
  | 9 | `prekeys` | `Bytes` |

  v1 (6 fields) and v2 (7 fields) cells are invalid, as is any table that is not exactly this one with version 3. The monitor scans these cells every `probe_interval_s` and keeps those whose network matches, whose `attestation_sig` is this monitor's `CSR-ATTEST-v2` signature over the cell's peer ID, service key, network, expiry, stake and the registry type hash, and whose stake is deposited.
- **Lifetime cap** (D24 A): `csr-registry` refuses an attestation that expires more than 8 days after the config cell clock. The monitor issues `expiry_ms = min(clock_ms + attest_validity_days, clock_ms + 8 days − 1 hour)` (`MAX_LIFETIME_MS`); `attest_validity_days` above 7 is a config error.
- **Endpoint** (F-MON-014): a registered runner whose cell has an `endpoint` is challenged there (pull mode, `POST <endpoint>/v1/challenge`), even when it is not a peer of the monitor's CKB node; it must answer with the registered `peer_id` and `service_pubkey` (otherwise `peer_id_mismatch` / `pubkey_changed`, retried after `discovery_backoff_s`). The endpoint must be an `http://` or `https://` URL without credentials, query or fragment whose host (every resolved address) is a public address, unless `allow_insecure_endpoints`; the rule is checked again before every probe (failure `endpoint_refused`). Redirects are never followed (a 3xx answer is a failed probe). Without an endpoint, discovery works through `get_peers` as before. The API never returns the raw endpoint, only `has_endpoint`.
- **Stake** (D-A7-1): the stake is a Nervos DAO deposit in the operator's wallet (D-A8-1: the registry owner may be any lock, CSR uses the runner's own wallet; the deposit owner consents with a signed message `CSR-STAKE-CONSENT-v1|<network>|<stake out point>|<service pubkey>|<peer id>`, digest `blake2b-256("Nervos Message:" ‖ text)`, which the `csr-registry` contract checks on creation and on every change of stake or owner, errors 21–23; the monitor therefore does not compare the owners). Out points are written `0x<64 hex>:<index decimal>`. It is **deposited** when `get_live_cell` says `live` and the cell has the DAO type script `{code_hash: 0x82d76d1b75fe2fd9a27dfbaa65a039221a380d76c926f378d3f81cf3e7e13f2e, hash_type: type, args: 0x}`, data of exactly 8 zero bytes, capacity ≥ `min_stake_ckb` (default 10 000 CKB). States: `deposited`; `withdrawn` (the cell is dead); `invalid` (anything else, with a reason: `not_found`, `not_dao`, `not_deposit`, `too_small`); `duplicate` (**one deposit, one registration**: of several registry cells naming the same deposit only the oldest – lowest block number, tx index, out point – counts). Only registrations with a deposited stake are valid.
- **Attestation policy** (`POST /v1/attest`): the binding signature must verify, the network must be the monitor's, and the node must be an active runner with that `peer_id` and at least `attest_min_ok_24h` (default 1) successful probes in the last 24 h; otherwise `403 not_eligible`. The `stake` must be a deposited DAO cell of at least `min_stake_ckb` (`403 stake_invalid` with a `reason`) not used by another peer's registration (`403 stake_in_use`); it is re-checked on every request, also when the cached attestation is returned. Validity = config cell `clock_ms` + `attest_validity_days` (default 7 days, at most 7), capped by the lifetime cap above. The attestation names the requested stake, which for a registered runner is tied to its registry (`stake_in_use`). The same attestation is returned from a cache for `attest_cache_s` (default 3600 s), only for the same stake.

## Ranking and stake

Every runner that answers the monitor is ranked whatever its stake (D29): the rank depends only on the score and on the other reasons above (`provisional`, `flagged`, `identity_unproven`), on every network and in every mode. A registration (Nervos DAO stake + registry cell) is needed only to receive Service Runtime jobs. The stake stays public: every item of `GET /v1/{network}/runners` carries `stake_status` (`deposited`, `withdrawn`, `invalid`, `duplicate` or `none`), `/v1/nodes/{peer_id}` carries the `stake` object, and the epoch leaf of a runner whose registry stake is `deposited` has the flag `FLAG_STAKED` (8). Apps such as CRT choose job runners only among leaves with `FLAG_STAKED`. Leaving the ranking ("Join off") means no longer answering the monitor. (Until D29, registry mode ranked only deposited registrations.)

## Score

`score_v1` is **frozen**. Score = 100 × (0.45·A30 + 0.15·A365 + 0.15·S30 + 0.15·F30 + 0.10·T), with weights A30 0.45, A365 0.15, S30 0.15, F30 0.15, T 0.10 (sum 1). A30/A365 are the availability over 30/365 days, S30 the share of ok probes in sync, F30 the share of passed P2P checks, T the age (capped at 365 days). The peer-count term P (5 %) was dropped; its weight went to A30 (decisions D11 B, D18 A). Any change to the formula needs `score_v2` and a new formula byte in the epoch (byte 29). A runner with the flag `identity_mismatch` or `bad_binding` scores 0.

## Epoch data and leaves

The epoch summary (`GET /v1/{network}/epochs/{n}`) carries `built_at` (unix seconds) and `late` (true when built more than 1 day after the epoch's end). An epoch counts as published only after its stat cell transaction is committed; the monitor publishes one epoch per pass (the newest unpublished one, older ones are skipped because each update replaces the data) and sends a dropped transaction again.

Every Monday 00:00 UTC (epoch boundaries) the monitor builds a Merkle tree over all ranked runners, sorted by runner_id.

Leaf (47 bytes): `runner_id(32) ‖ score×100 u16 ‖ a30×10000 u16 ‖ a365×10000 u16 ‖ f30×10000 u16 ‖ country(2 ASCII, "??" unknown) ‖ asn u32 ‖ flags u8` (flags: 1 provisional, 2 identity mismatch, 4 bad binding, 8 `FLAG_STAKED` = deposited registry stake, D29).

Epoch data is a fixed binary layout of 159 bytes (not Molecule), stored as the stat cell data:

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

`GET /v1/{network}/epochs` returns all epochs in one reply (`{"items": [...]}`); the list is not paged and `limit` and `cursor` are ignored.

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
