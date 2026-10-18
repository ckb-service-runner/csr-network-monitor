"""On-chain duties for CSR's registry: config cell clock, registry scan, attestations."""
import copy

from . import crypto, csrchain, molecule, ping, protocol, stat_cell
from .hashing import blake160, from_hex, to_hex

DAY_MS = 86_400_000


class ConfigCellError(Exception):
    pass


def config_type_script(args):
    return {"code_hash": stat_cell.TYPE_ID_CODE_HASH, "hash_type": "type", "args": args}


def config_type_hash(args):
    return molecule.script_hash(config_type_script(args))


class ConfigCellWriter:
    def __init__(self, store, chain, config, secret):
        self.store, self.chain, self.config, self.secret = store, chain, config, secret
        self.pubkey = crypto.pubkey_from_secret(secret)

    def find(self):
        if not self.config.config_type_args:
            return None
        ts = config_type_script(self.config.config_type_args)
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
        return self._parse(self._cell())["clock_ms"]

    def update_clock(self):
        c = self.config
        cell = self._cell()
        lock = {"code_hash": c.stat_cell_sighash_code_hash,
                "hash_type": c.stat_cell_sighash_hash_type, "args": to_hex(blake160(self.pubkey))}
        out = copy.deepcopy(cell["output"])
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
        if clock_ms <= parsed["clock_ms"]:
            return None
        data = bytearray(from_hex(cell["output_data"]))
        data[33:41] = clock_ms.to_bytes(8, "little")
        data = bytes(data)
        cap = int(out["capacity"], 16) - c.clock_update_fee_shannons
        out["capacity"] = hex(cap)
        if cap < stat_cell.occupied_capacity(out, data):
            raise ConfigCellError("config cell cannot pay the fee")
        tx = {
            "version": "0x0",
            "cell_deps": [{"out_point": {"tx_hash": c.stat_cell_sighash_dep_tx,
                                         "index": hex(c.stat_cell_sighash_dep_index)},
                           "dep_type": "dep_group"}],
            "header_deps": [],
            "inputs": [{"since": "0x0", "previous_output": cell["out_point"]}],
            "outputs": [out],
            "outputs_data": [to_hex(data)],
            "witnesses": ["0x"],
        }
        tx = stat_cell.sign_input_group(tx, self.secret, [0])
        h = self.chain.send_transaction(tx)
        self.store.set_meta("config_clock_ms", str(clock_ms))
        return h


def scan_registry(store, chain, config, monitor_pubkey):
    if not config.csr_registry_code_hash or not config.config_type_args:
        return None
    script = {"code_hash": config.csr_registry_code_hash, "hash_type": config.csr_registry_hash_type,
              "args": config_type_hash(config.config_type_args)}
    nid = csrchain.NETWORK_IDS[config.network]
    rows, invalid = [], 0
    for c in chain.get_cells(script, "type", exact=True):
        try:
            reg = csrchain.parse_registry(from_hex(c.get("output_data") or "0x"))
        except ValueError:
            invalid += 1
            continue
        att = reg["attestation"]
        if (reg["network"] == nid and att["network_id"] == nid
                and att["peer_id"] == reg["peer_id"]
                and att["service_pubkey"] == reg["service_pubkey"]
                and csrchain.verify_attestation(att, monitor_pubkey)):
            op = c["out_point"]
            rows.append({"peer_id": reg["peer_id"], "service_pubkey": reg["service_pubkey"],
                         "expiry_ms": att["expiry_ms"],
                         "outpoint": f"{op['tx_hash']}:{int(op['index'], 16)}"})
        else:
            invalid += 1
    store.set_registrations(rows)
    return {"valid": len(rows), "invalid": invalid}


class Attester:
    def __init__(self, store, config, secret, writer):
        self.store, self.config, self.secret, self.writer = store, config, secret, writer

    def handle_attest(self, body, ip, now):
        keys = ("peer_id", "service_pubkey", "binding_sig", "network")
        if not isinstance(body, dict) or not all(isinstance(body.get(k), str) for k in keys):
            return 400, {"error": "bad_request"}
        peer, svc, sig, network = (body[k] for k in keys)
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
        last = self.store.last_issued(peer, svc)
        if last is not None and 0 <= now - last["issued_at"] < self.config.attest_cache_s:
            return 200, last["attestation"]
        try:
            clock_ms = self.writer.read_clock()
        except Exception:
            return 503, {"error": "chain_unavailable"}
        att = csrchain.sign_attestation(
            self.secret, peer_id=peer, service_pubkey=svc, network=network,
            expiry_ms=clock_ms + self.config.attest_validity_days * DAY_MS)
        self.store.save_issued(peer, svc, issued_at=now, attestation=att)
        return 200, att
