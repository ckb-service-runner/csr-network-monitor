# Decisions

- Phase 1: secp256k1 uses affine coordinates with `pow(x, -1, p)`; fast enough (<20 ms per operation).
- Phase 1: config validation of `node_rpc` uses urllib.parse; ports and paths are allowed, userinfo is not checked.
- Phase 3: GeoDB keeps IPv4 ranges in array('I'); a (runner, slot) conflict is detected via INSERT OR IGNORE. Country table maps TF to AN, UM to NA.

## Phase 4
- `RpcChain.block_at_time` reads genesis first (0 if later than ts), then binary-searches up to the tip.
- `get_cells` stops at the first empty page or a missing/empty cursor.
- Registry: a cell whose out_point cannot be parsed counts as invalid; opt-in changes count as "updated".
