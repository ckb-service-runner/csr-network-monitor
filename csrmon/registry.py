"""Registration discovery from registration cells."""
from . import protocol
from .hashing import to_hex


def _fields(reg, outpoint):
    return {
        "service_pubkey": to_hex(reg.service_pubkey),
        "peer_id": reg.peer_id,
        "p2p_pubkey": to_hex(reg.p2p_pubkey),
        "reg_outpoint": outpoint,
        "mode": reg.mode,
        "endpoint": reg.endpoint,
        "p2p_port": reg.p2p_port,
        "ranking_opt_in": reg.ranking_opt_in,
    }


def _endpoint_ok(reg, config):
    if reg.mode != "pull":
        return True
    if reg.endpoint.startswith("https://"):
        return True
    return bool(config.allow_insecure_endpoints) and reg.endpoint.startswith("http://")


def sync_registrations(store, chain, config, now):
    result = {"added": [], "updated": [], "removed": [], "invalid": 0}
    if not config.registration_code_hash:
        return result
    script = {"code_hash": config.registration_code_hash,
              "hash_type": config.registration_hash_type,
              "args": config.registration_args}
    seen = {}
    for c in chain.get_cells(script, "type", exact=False):
        try:
            reg = protocol.decode_registration(bytes.fromhex(c["output_data"][2:]))
            op = c["out_point"]
            outpoint = f"{op['tx_hash']}:{int(op['index'], 16)}"
        except Exception:
            result["invalid"] += 1
            continue
        if reg.network != config.network or not _endpoint_ok(reg, config):
            result["invalid"] += 1
            continue
        rid = reg.runner_id
        if rid in seen:
            result["invalid"] += 1
            continue
        seen[rid] = _fields(reg, outpoint)

    for rid, f in seen.items():
        old = store.get_runner(rid)
        if old is None:
            store.upsert_runner(rid, now=now, **f)
            result["added"].append(rid)
        elif old["status"] == "deregistered" or any(old[k] != v for k, v in f.items()):
            store.upsert_runner(rid, now=now, **f)
            result["updated"].append(rid)

    for r in store.list_runners(("active", "opted_out")):
        if r["runner_id"] not in seen:
            store.set_status(r["runner_id"], "deregistered")
            result["removed"].append(r["runner_id"])
    for k in ("added", "updated", "removed"):
        result[k].sort()
    return result
