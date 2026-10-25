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
- `CSR-ATTEST-v2` (monitor-v3, D21 A): attestation digest = `ckb_blake2b("CSR-ATTEST-v2" ‖ AttestationBodyV2)` with
  `AttestationBodyV2 = table { peer_id: Bytes, service_pubkey: Byte33, network: byte, expiry_ms: Uint64, stake: OutPoint, registry_type_hash: Byte32 }`.
  The signature (65 bytes `r ‖ s ‖ recid`) thus names the stake out point and the type hash of the `csr-registry` script it is valid for. The older `CSR-ATTEST-v1` (body without `stake` and `registry_type_hash`) is no longer issued or accepted.

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

### `POST /v1/attest`

Body `{"peer_id","service_pubkey","binding_sig","network","stake"}` (`stake` = out point text `0x<64 hex>:<index>` of the Nervos DAO deposit); reply is CSR's attestation file `{"version": 2, "peer_id","service_pubkey","network","network_id","expiry_ms","stake","registry_type_hash","signature","monitor_pubkey"}` (input of `csr register prepare`): `stake` is the requested out point (normalised to lowercase), `registry_type_hash` the type hash of this monitor's `csr-registry` script (also in `GET /v1/monitor` as `csr_registry_type_hash`), `signature` the `CSR-ATTEST-v2` signature (`0x` + 130 hex).

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
| 503 | `chain_unavailable`, `unavailable` | config cell clock unreadable / attestations not configured (`config_type_args`, `config_type_code_hash`, `csr_registry_code_hash`) |

### `GET /v1/network` and `GET /v1/nodes/{peer_id}`

Read by the CSR dashboard (see `spec/monitor-public-api.md`). `/v1/network` returns `nodes_total`, `nodes_reachable` (probed ok within `reachable_window_s`), `countries` and `updated_at`. `/v1/nodes/{peer_id}` returns the ranking data, `attestation` and a `stake` object `{"status": "deposited"|"withdrawn"|"invalid"|"duplicate"|"none", "capacity_ckb": int|null, "outpoint": string|null}`, plus the ranking data of a node with `check_type` (`p2p_verified` / `challenge_only`); status 404 `not_ranked` for nodes that are unknown or still provisional. `GET /v1/monitor` returns the monitor public key, version, tip, `stat_cell_type_hash`, `csr_config_type_hash`, `csr_registry_type_hash` and `csr_registry_code_hash`.

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
- **`p2p_verified` vs `challenge_only`**: a probe is `p2p_verified` when the answering `peer_id` is a node ID the monitor's CKB node is connected to (for discovery: the peer that was probed). A node is reported as `p2p_verified` if any successful probe of the last 24 h was P2P-verified, else `challenge_only`.

## Slots and the grace rule

slot = `int(ts // probe_interval_s)`. At most one outcome is recorded per runner per slot. Inbound runners are challenged once per slot. Outbound runners must check in during the slot; a check-in in the first half of the next slot still counts for the previous slot (grace), after that the slot is closed as `fail` (`no_checkin`). Slots during which probing is paused are `excluded`, never misses. Slots before the monitor started or before the runner was first seen are not counted.

## Registry, config cell and attestations

- The monitor owns the **config cell**: type script **`csr-config-type`** `{code_hash: config_type_code_hash, hash_type: config_type_hash_type (default data2), args: config_type_args}` (monitor-v3; before it was a Type ID script), lock = the monitor key's secp256k1 sighash lock. Data = `monitor_pubkey (33) ‖ clock_ms (u64 LE) ‖ 8 reserved bytes`. Every `clock_update_interval_s` the monitor spends it into the same lock/type with `clock_ms` = timestamp of the chain tip; the fee is taken from the cell capacity. The transaction has the sighash dep group and the `csr-config-type` code cell (`config_type_dep_tx`/`config_type_dep_index`, dep type `code`) as cell deps. **The clock only moves forward and the key never changes**: the monitor skips the update when the tip timestamp is not newer than `clock_ms` and copies the key and the reserved bytes unchanged; the contract refuses anything else anyway.
- **Registry cell** (`csr-registry`, **Registry v3**): type script `{code_hash: csr_registry_code_hash, hash_type: csr_registry_hash_type (default data2), args: config cell type hash}`; its type hash is the **registry type hash** that the attestation names. Lock `csr-dual-lock` with 32- or 64-byte args. Data is a molecule table with 10 fields:

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
