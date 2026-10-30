"""On-chain duties for CSR's registry: config cell clock, registry scan, attestations."""
import copy
import logging
import time

from . import crypto, csrchain, molecule, ping, protocol, stake, stat_cell
from .hashing import blake160, from_hex, to_hex

DAY_MS = 86_400_000
log = logging.getLogger("csrmon")


def clock_fresh(*, clock_ms, now_s, max_age_s) -> bool:
    """True when the on-chain clock is at most `max_age_s` old."""
    return now_s - clock_ms / 1000 <= max_age_s


HOUR_MS = 3_600_000
# csr-registry refuses an attestation expiring more than 8 days beyond the config cell clock
# (D24 A); one hour of margin covers the clock moving between signing and the runner's tx.
MAX_LIFETIME_MS = 8 * DAY_MS - HOUR_MS


class ConfigCellError(Exception):
    pass


def config_type_script(args, code_hash, hash_type="data2"):
    """The `csr-config-type` script of the config cell."""
    return {"code_hash": code_hash, "hash_type": hash_type, "args": args}


def config_type_hash(args, code_hash, hash_type="data2"):
    return molecule.script_hash(config_type_script(args, code_hash, hash_type))


def configured(config) -> bool:
    return bool(config.config_type_args and config.config_type_code_hash)


def config_script_of(config):
    return config_type_script(config.config_type_args, config.config_type_code_hash,
                              config.config_type_hash_type)


def config_hash_of(config):
    """Type hash of this monitor's config cell, None when not configured."""
    return molecule.script_hash(config_script_of(config)) if configured(config) else None


def registry_type_hash(code_hash, hash_type, config_type_args) -> str:
    """Type hash of `{code_hash, hash_type, args}`: the `csr-registry` type script, whose args
    is the config cell's type hash (passed here as `config_type_args`)."""
    return molecule.script_hash({"code_hash": code_hash, "hash_type": hash_type,
                                 "args": config_type_args})


def registry_script_of(config):
    return {"code_hash": config.csr_registry_code_hash, "hash_type": config.csr_registry_hash_type,
            "args": config_hash_of(config)}


def registry_hash_of(config):
    """Type hash of this monitor's `csr-registry` script, None when not configured."""
    if not configured(config) or not config.csr_registry_code_hash:
        return None
    return registry_type_hash(config.csr_registry_code_hash, config.csr_registry_hash_type,
                              config_hash_of(config))


class ConfigCellWriter:
    def __init__(self, store, chain, config, secret):
        self.store, self.chain, self.config, self.secret = store, chain, config, secret
        self.pubkey = crypto.pubkey_from_secret(secret)

    def find(self):
        if not configured(self.config):
            return None
        ts = config_script_of(self.config)
        for c in self.chain.get_cells(ts, "type", exact=True):
            return c
        return None

    def _cell(self):
        cell = self.find()
        if cell is None:
            raise ConfigCellError("config cell not found")
        return cell

    @staticmethod
    def _parse(cell):
        try:
            return csrchain.parse_config_cell(from_hex(cell.get("output_data") or "0x"))
        except ValueError as e:
            raise ConfigCellError(str(e)) from e

    def read_clock(self) -> int:
        cell = self._cell()
        clock_ms = self._parse(cell)["clock_ms"]
        self.store.set_meta("clock_ms", str(clock_ms))
        self._note_spare(cell)
        return clock_ms

    def _note_spare(self, cell):
        """Remember the capacity above the occupied capacity; warn when it runs low."""
        try:
            data = from_hex(cell.get("output_data") or "0x")
            spare = int(cell["output"]["capacity"], 16) - stat_cell.occupied_capacity(
                cell["output"], data)
        except (KeyError, TypeError, ValueError):
            return
        self.store.set_meta("config_cell_spare_shannons", str(spare))
        fee = self.config.clock_update_fee_shannons
        per_day = fee * 86400 / self.config.clock_update_interval_s
        if spare < 30 * per_day:
            log.warning("config cell has %.2f CKB spare, which covers fewer than 30 days of clock"
                        " updates; refill it", spare / stat_cell.CKB)

    def update_clock(self):
        c = self.config
        cell = self._cell()
        lock = {"code_hash": c.stat_cell_sighash_code_hash,
                "hash_type": c.stat_cell_sighash_hash_type, "args": to_hex(blake160(self.pubkey))}
        out = copy.deepcopy(cell["output"])
        if out.get("type") != config_script_of(c):
            raise ConfigCellError("config cell has another type script")
        if out["lock"] != lock:
            raise ConfigCellError("config cell is not locked by the monitor key")
        parsed = self._parse(cell)
        if parsed["monitor_pubkey"] != to_hex(self.pubkey):
            raise ConfigCellError("config cell holds another monitor pubkey")
        tip, _ = self.chain.tip()
        header = self.chain.header(tip)
        if header is None:
            raise ConfigCellError("tip header unavailable")
        clock_ms = header["timestamp_ms"]
        self._note_spare(cell)
        if clock_ms <= parsed["clock_ms"]:
            self.store.set_meta("clock_ms", str(parsed["clock_ms"]))
            return None
        # csr-config-type: the key (bytes 0..33) is copied unchanged and the clock only moves
        # forward (checked above); the contract refuses anything else anyway.
        old = from_hex(cell["output_data"])
        data = old[:33] + clock_ms.to_bytes(8, "little") + old[41:]
        cap = int(out["capacity"], 16) - c.clock_update_fee_shannons
        out["capacity"] = hex(cap)
        if cap < stat_cell.occupied_capacity(out, data):
            raise ConfigCellError("config cell cannot pay the fee")
        if not c.config_type_dep_tx:
            raise ConfigCellError("config_type_dep_tx is not set")
        tx = {
            "version": "0x0",
            "cell_deps": [{"out_point": {"tx_hash": c.stat_cell_sighash_dep_tx,
                                         "index": hex(c.stat_cell_sighash_dep_index)},
                           "dep_type": "dep_group"},
                          {"out_point": {"tx_hash": c.config_type_dep_tx,
                                         "index": hex(c.config_type_dep_index)},
                           "dep_type": "code"}],
            "header_deps": [],
            "inputs": [{"since": "0x0", "previous_output": cell["out_point"]}],
            "outputs": [out],
            "outputs_data": [to_hex(data)],
            "witnesses": ["0x"],
        }
        tx = stat_cell.sign_input_group(tx, self.secret, [0])
        h = self.chain.send_transaction(tx)
        self.store.set_meta("config_clock_ms", str(clock_ms))
        self.store.set_meta("clock_ms", str(clock_ms))
        spare = cap - stat_cell.occupied_capacity(out, data)
        self.store.set_meta("config_cell_spare_shannons", str(spare))
        return h


def scan_registry(store, chain, config, monitor_pubkey):
    """Keep the Registry v3 cells of this network and monitor that are backed by a live DAO
    deposit of at least `min_stake_ckb`; the deposit owner's consent is checked by the
    `csr-registry` contract (D-A8-1), so the registry owner may differ from the deposit owner.
    The CSR-ATTEST-v2 signature names the stake and the registry type hash (D21 A)."""
    if not config.csr_registry_code_hash or not configured(config):
        return None
    script = registry_script_of(config)
    type_hash = molecule.script_hash(script)
    nid = csrchain.NETWORK_IDS[config.network]
    cands, invalid = [], 0
    for c in chain.get_cells(script, "type", exact=True):
        try:
            reg = csrchain.parse_registry_v3(from_hex(c.get("output_data") or "0x"))
            args = from_hex(c["output"]["lock"]["args"])
            if len(args) not in (32, 64):
                raise ValueError("bad lock args")
        except (ValueError, KeyError, TypeError):
            invalid += 1
            continue
        if not (reg["network"] == nid
                and csrchain.verify_registry_v3(reg, monitor_pubkey, type_hash)):
            invalid += 1
            continue
        op = c["out_point"]
        res = stake.check_stake(chain, reg["stake"], min_stake_ckb=config.min_stake_ckb)
        cands.append({"peer_id": reg["peer_id"], "service_pubkey": reg["service_pubkey"],
                      "reg_outpoint": f"{op['tx_hash']}:{int(op['index'], 16)}",
                      "expiry_ms": reg["expiry_ms"], "stake_outpoint": reg["stake"],
                      "endpoint": reg["endpoint"],
                      "status": res["status"], "capacity_ckb": res["capacity_ckb"],
                      "reason": res["reason"],
                      "_order": (int(c["block_number"], 16), int(c["tx_index"], 16))})
    cands.sort(key=lambda r: (*r["_order"], r["reg_outpoint"]))
    used = set()
    for r in cands:
        del r["_order"]
        if r["status"] == "deposited":
            if r["stake_outpoint"] in used:
                r["status"], r["reason"] = "duplicate", "stake_in_use"
            else:
                used.add(r["stake_outpoint"])
    good = [r for r in cands if r["status"] == "deposited"]
    store.set_registrations([{"peer_id": r["peer_id"], "service_pubkey": r["service_pubkey"],
                              "expiry_ms": r["expiry_ms"], "outpoint": r["reg_outpoint"],
                              "endpoint": r["endpoint"]}
                             for r in good])
    store.set_stakes(cands)
    store.set_meta("registry_last_scan_at", str(int(time.time())))
    return {"valid": len(good), "invalid": invalid, "no_stake": len(cands) - len(good)}


def attest_expiry_ms(clock_ms, validity_days) -> int:
    """Never beyond the on-chain lifetime cap (D24 A)."""
    return min(clock_ms + validity_days * DAY_MS, clock_ms + MAX_LIFETIME_MS)


class Attester:
    def __init__(self, store, config, secret, writer):
        self.store, self.config, self.secret, self.writer = store, config, secret, writer

    def handle_attest(self, body, ip, now):
        keys = ("peer_id", "service_pubkey", "binding_sig", "network", "stake")
        if not isinstance(body, dict) or not all(isinstance(body.get(k), str) for k in keys):
            return 400, {"error": "bad_request"}
        peer, svc, sig, network, stake_op = (body[k] for k in keys)
        try:
            stake_op = csrchain.format_outpoint(*csrchain.parse_outpoint(stake_op))
        except ValueError:
            return 400, {"error": "bad_request"}
        if network != self.config.network:
            return 400, {"error": "wrong_network"}
        if not ping.verify_binding(peer, svc, network, sig):
            return 401, {"error": "bad_signature"}
        try:
            rid = protocol.runner_id(from_hex(svc))
        except Exception:
            return 401, {"error": "bad_signature"}
        runner = self.store.get_runner(rid)
        if (runner is None or runner["status"] != "active" or runner["peer_id"] != peer
                or sum(1 for p in self.store.probes(rid, since=now - 86400, until=now + 1)
                       if p["result"] == "ok") < self.config.attest_min_ok_24h):
            return 403, {"error": "not_eligible"}
        try:
            st = stake.check_stake(self.writer.chain, stake_op,
                                   min_stake_ckb=self.config.min_stake_ckb)
        except Exception:
            return 503, {"error": "chain_unavailable"}
        if st["status"] != "deposited":
            return 403, {"error": "stake_invalid", "reason": st["reason"]}
        user = self.store.stake_user(stake_op)
        if user is not None and user != peer:
            return 403, {"error": "stake_in_use"}
        rows = self.store.stakes_for(peer, svc)
        if rows and not any(r["stake_outpoint"] == stake_op and r["status"] == "deposited"
                            for r in rows):
            return 403, {"error": "stake_mismatch"}
        last = self.store.last_issued(peer, svc)
        if (last is not None and 0 <= now - last["issued_at"] < self.config.attest_cache_s
                and last["attestation"].get("version") == 2
                and last["attestation"].get("stake") == stake_op):
            return 200, last["attestation"]
        try:
            clock_ms = self.writer.read_clock()
        except Exception:
            return 503, {"error": "chain_unavailable"}
        if not clock_fresh(clock_ms=clock_ms, now_s=now,
                           max_age_s=self.config.attest_max_clock_age_s):
            return 503, {"error": "clock_stale"}
        type_hash = registry_hash_of(self.config)
        if type_hash is None:
            return 503, {"error": "unavailable"}
        att = csrchain.sign_attestation_v2(
            self.secret, peer_id=peer, service_pubkey=svc, network=network,
            expiry_ms=attest_expiry_ms(clock_ms, self.config.attest_validity_days),
            stake=stake_op, registry_type_hash=type_hash)
        self.store.save_issued(peer, svc, issued_at=now, attestation=att)
        return 200, att
