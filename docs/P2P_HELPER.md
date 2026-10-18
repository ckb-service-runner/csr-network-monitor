# P2P helper contract

The full-node check runs an external command (`p2p_check_cmd`, split with shell quoting rules, no shell). Per runner the monitor starts the command, writes one JSON object to stdin and reads one JSON object from stdout. The helper may take up to `p2p_check_timeout_s` (default 120 s); the check runs in its own thread so it never blocks probing. Without a helper the P2P term of the score is 0 for everybody.

## Request

```json
{"v":1,"network":"testnet","peer_id":"Qm…","address":"/ip4/203.0.113.7/tcp/8115",
 "heights":[12,830,99120,99800],"timeout_s":120}
```

- `peer_id`: the peer ID the runner registered; the helper must authenticate the remote with the secio/tentacle handshake and report the ID it actually saw.
- `address`: multiaddr built from the endpoint host and the registered `p2p_port` (`null` if unknown, e.g. push mode); the helper may use other discovery then.
- `heights`: block numbers the node must be able to serve (a mix of recent and old ones).
- `timeout_s`: total time budget.

## Response

```json
{"peer_id_seen":"Qm…","served":[{"height":12,"hash":"0x…"}],"latency_ms":143}
```

- `peer_id_seen`: ID of the connected peer (`null` if none).
- `served`: for every height the peer delivered, the block hash from the peer's own data. The monitor compares each hash with its own node; a missing or wrong entry counts as not served.
- `latency_ms`: handshake or first-block latency (integer, optional).

Exit code `0` with valid JSON means a result; any other exit code, invalid JSON, a missing `served` list or a timeout is recorded as `error`.

Outcome: `ok` (peer ID matches and all heights served), `fail` (not all served or no peer seen), `identity_mismatch` (the seen ID differs from the registered one; sets a flag on the runner), `error` (helper problem).

## What a real helper must do

1. Open a TCP connection to `address` and run the CKB P2P (tentacle) handshake with a throwaway key, reading the remote peer ID.
2. Open the Identify and Sync/Relay protocols, check the network (chain spec) matches.
3. Request each height through the sync protocol (`GetHeaders`/`GetBlocks`) and return the block hash of what the peer sent.
4. Never trust data without verifying it: hash the header received, do not copy a claimed hash.
5. Respect `timeout_s`, print only the JSON object on stdout, logs to stderr.
