# CSR wire protocol (v1)

This is the contract between the CSR Network Monitor and a CSR (CKB Service Runner) implementation.

## Primitives

- **Hash**: `ckb_blake2b(x)` = BLAKE2b-256 with personalization `b"ckb-default-hash"` (the `ckb-default-hash` of CKB). `blake160(x)` is its first 20 bytes.
- **Hex**: `"0x"` + lowercase hex. Integers in binary structures are little-endian.
- **Signature**: secp256k1, 65 bytes `r(32) ‖ s(32) ‖ recid(1)`, always over a 32-byte digest, deterministic nonce (RFC 6979, HMAC-SHA256), low-s (`s ≤ n/2`). Verifiers reject high-s.
- **canonical JSON** (also called canonical form): `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")`.
- **runner_id** = `"0x" + hex(ckb_blake2b(service_pubkey))` (33-byte compressed key).
- **peer_id** = base58(`0x12 0x20 ‖ sha256(p2p_pubkey)`), starts with `Qm`.
- **slot** = `int(ts // probe_interval_s)`; time is Unix seconds (UTC).

## Domain separators

ASCII strings prefixed to signed data: `CSR/v1/challenge`, `CSR/v1/probe`, `CSR/v1/bind`, `CSR/v1/checkin`, `CSR/v1/epoch`.

## Challenge (monitor → runner)

```json
{"v":1,"network":"testnet","nonce":"0x…32 bytes","issued_at":1760000000,
 "monitor_tip":123456,"block_height":123400,"monitor_sig":"0x…65 bytes"}
```

`monitor_sig` signs `ckb_blake2b("CSR/v1/challenge" ‖ canonical_json(challenge without monitor_sig))`. The monitor public key is published at `GET /v1/monitor`. A runner should verify the signature and that `network` is its own.

## Response (runner → monitor)

```json
{"v":1,"nonce":"0x…same nonce","peer_id":"Qm…","tip_number":123455,"tip_hash":"0x…",
 "block_hash":"0x…hash of block_height","ibd":false,"peers_out":8,
 "csr_version":"0.1.0","ckb_version":"0.203.0","sig":"0x…"}
```

`block_hash` is the hash of the block at the challenge's `block_height`, `tip_*` describe the runner's own CKB node. The service key signs
`ckb_blake2b("CSR/v1/probe" ‖ ckb_blake2b(canonical_json(challenge)) ‖ ckb_blake2b(canonical_json(response without sig)))`.

The monitor marks a probe `fail` for: `bad_format`, `late` (slower than `probe_timeout_s`), `bad_nonce`, `bad_signature`, `peer_id_mismatch`, `wrong_block_hash`, `unknown_tip` (tip hash unknown or tip ahead of the monitor by more than `sync_threshold`), plus transport reasons `timeout`, `unreachable`, `bad_status`, `no_response`. A correct answer more than `sync_threshold` blocks behind (or with `ibd` true) is *answered* but *not in sync*.

## Pull mode: `POST /csr/v1/probe`

The monitor posts the challenge (canonical JSON, `Content-Type: application/json`) to `<endpoint>/csr/v1/probe` and expects `200` with the response JSON. Any other status counts as `bad_status`.

## Push mode (runner behind NAT)

1. `POST /v1/{network}/checkin` with `{"v":1,"runner_id":"0x…","ts":<unix>,"sig":"0x…"}`.
   `sig` signs `ckb_blake2b("CSR/v1/checkin" ‖ network_ascii ‖ runner_id_bytes(32) ‖ ts as u64 LE)`.
2. On `200` the body is `{"challenge": {…}, "deadline_s": <probe_timeout_s>}`.
3. `POST /v1/{network}/checkin/response` with `{"runner_id":"0x…","response":{…}}` before the deadline.
   `200` returns `{"result":"ok"|"fail","failure_reason":…,"lag":…,"in_sync":…}`.

Status codes:

| Endpoint | Status | Body `error` | Meaning |
|---|---|---|---|
| checkin | 200 | – | challenge issued |
| checkin | 400 | `bad_request`, `stale_timestamp` | malformed body; `ts` more than 120 s from the monitor clock |
| checkin | 401 | `bad_signature` | signature invalid |
| checkin | 404 | `unknown_runner` | not registered / not active |
| checkin | 413 | `too_large` | body above 16384 bytes |
| checkin | 429 | `slot_done`, `challenge_open`, `rate_limited` | the slot already has an outcome; a challenge is already open; too many requests |
| checkin | 503 | `monitor_paused`, `unavailable` | monitor paused (tip cross-check) or push unavailable |
| response | 200 | – | evaluated; see `result` |
| response | 400 | `bad_request` | malformed body |
| response | 409 | `no_open_challenge` | no check-in pending (or it expired: recorded as `no_response`) |
| response | 413 | `too_large` | body too large |

At most one outcome is recorded per runner per slot, so extra check-ins do not raise availability.

## Registration cell (v1)

The registration cell is created on chain by the operator.

Cell data (type script configurable by the monitor):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version = 1 |
| 1 | 1 | network: 0 testnet, 1 mainnet |
| 2 | 1 | mode: 0 pull, 1 push |
| 3 | 1 | flags: bit 0 = "Join the node ranking" (other bits must be 0) |
| 4 | 33 | service public key |
| 37 | 33 | P2P public key |
| 70 | 65 | bind signature |
| 135 | 2 | p2p_port (LE) |
| 137 | 2 | endpoint length n (LE) |
| 139 | n | endpoint URL, UTF-8 (pull: required; push: empty) |

The bind signature is made with the P2P key over `ckb_blake2b("CSR/v1/bind" ‖ service_pubkey ‖ network_ascii)`. Cells with a wrong bind signature, wrong network or a malformed layout are ignored. An unset opt-in flag hides the runner and stops probing.

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
