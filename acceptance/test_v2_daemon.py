"""v2 Phase 8 acceptance: the running daemon end to end with a fake CKB node, a fake inbound CSR
node found through get_peers, a fake outbound CSR node, the config cell and a registry cell."""
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.request

from csrmon import configcell, crypto, csrchain, molecule, ping, stat_cell
from csrmon.hashing import blake160, from_hex, to_hex
from fakes import FakeRpcServer, cell
from fakes_v2 import FakeChainV2, FakeCSR, peer_entry
from fakes_stake import FakeChainStake, dao_live, dual_lock
from fakes_v3 import CONFIG_CODE, CONFIG_DEP_TX, config_type, registry_type, registry_v3_data

STAKE = "0x" + "5e" * 32 + ":0"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIGHASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
CONFIG_ARGS = "0x" + "a9" * 32
REGISTRY_CODE = "0x" + "47" * 32
CKB = 10 ** 8


def sk(n):
    return n.to_bytes(32, "big")


class Rpc(FakeRpcServer):
    def dispatch(self, method, params):
        if method == "get_peers":
            return self.chain.peers
        if method == "get_live_cell":
            op = params[0]
            return self.chain.get_live_cell(op["tx_hash"], int(op["index"], 16))
        return super().dispatch(method, params)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http(method, url, obj=None):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw


def wait_for(fn, timeout, step=0.3):
    end, last = time.time() + timeout, None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:     # noqa: BLE001
            last = e
        time.sleep(step)
    raise AssertionError(f"timed out, last={last!r}")


def test_end_to_end(tmp_path):
    data = tmp_path / "data"
    cfg_path = tmp_path / "monitor.toml"

    def write_cfg(**kv):
        cfg_path.write_text("".join(f"{k} = {v}\n" for k, v in kv.items()))

    base = {"network": '"testnet"', "public_url": '"https://monitor-testnet.vericell.net"',
            "db_path": f'"{data}/t.db"', "key_path": f'"{data}/k.key"'}
    write_cfg(**base)
    r = subprocess.run([sys.executable, "-m", "csrmon", "keygen", "--config", str(cfg_path)], cwd=ROOT,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    mon_secret = bytes.fromhex((data / "k.key").read_text().strip()[2:])
    mon_pk = to_hex(crypto.pubkey_from_secret(mon_secret))

    fc = FakeChainStake(tip=12_000_000)
    lock = {"code_hash": SIGHASH, "hash_type": "type", "args": to_hex(blake160(from_hex(mon_pk)))}
    ctype = config_type(CONFIG_ARGS)
    fc.cells.append(cell(ctype, to_hex(csrchain.config_cell_data(from_hex(mon_pk), 1_000)),
                         "0x" + "c0" * 32, 0, capacity=10_000 * CKB, lock=lock))
    clock_txs = []

    def on_send(tx):
        h = molecule.tx_hash(tx)
        if tx["outputs"] and tx["outputs"][0].get("type") == ctype:
            clock_txs.append(tx)
            fc.cells = [c for c in fc.cells if c["output"].get("type") != ctype]
            fc.cells.append({"output": tx["outputs"][0], "output_data": tx["outputs_data"][0],
                             "out_point": {"tx_hash": h, "index": "0x0"}, "block_number": "0x1",
                             "tx_index": "0x0"})
        return h

    fc.on_send = on_send
    inbound = FakeCSR(sk(1), "QmInbound", fc, mon_pk)
    outbound = FakeCSR(sk(2), "QmOutbound", fc, mon_pk)
    inbound.__enter__()
    fc.peers = [peer_entry("QmInbound", ["/ip4/127.0.0.1/tcp/8115/p2p/QmInbound"]),
                peer_entry("QmOutbound", ["/ip4/127.0.0.2/tcp/8115"])]
    # a registry cell for the inbound node, attested by this monitor
    rtype = registry_type(REGISTRY_CODE, CONFIG_ARGS)
    fc.cells.append(cell(rtype, registry_v3_data(mon_secret, peer="QmInbound", service_pubkey=inbound.service_pubkey,
                                                 stake=STAKE, expiry_ms=1_900_000_000_000,
                                                 type_hash=molecule.script_hash(rtype)),
                         "0x" + "e1" * 32, 0, lock=dual_lock(1)))
    fc.live[STAKE] = dao_live(1, 10_000)
    rpc = Rpc(fc)
    rpc.__enter__()
    port = free_port()
    write_cfg(**base, node_rpc=f'"{rpc.url}"', listen_port=port, probe_interval_s=3, probe_jitter_s=0,
              probe_timeout_s=3, aggregate_interval_s=1, discovery_interval_s=1, ping_port=inbound.port,
              config_type_args=f'"{CONFIG_ARGS}"', csr_registry_code_hash=f'"{REGISTRY_CODE}"',
              config_type_code_hash=f'"{CONFIG_CODE}"', config_type_dep_tx=f'"{CONFIG_DEP_TX}"',
              stat_cell_sighash_dep_tx=f'"0x{"5d" * 32}"', clock_update_interval_s=2)
    proc = subprocess.Popen([sys.executable, "-m", "csrmon", "run", "--config", str(cfg_path)], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    url = f"http://127.0.0.1:{port}"
    try:
        mon = wait_for(lambda: http("GET", url + "/v1/monitor")[1], 30)
        assert mon["pubkey"] == mon_pk and mon["network"] == "testnet"
        assert mon["csr_config_type_hash"] == configcell.config_type_hash(CONFIG_ARGS, CONFIG_CODE)
        assert mon["csr_registry_type_hash"] == molecule.script_hash(rtype)
        assert mon["csr_registry_code_hash"] == REGISTRY_CODE

        # the inbound node is discovered through get_peers and probed on /v1/challenge
        wait_for(lambda: http("GET", url + "/v1/network")[1]["nodes_total"] >= 1, 40)
        assert any(path == "/v1/challenge" for path, _ in inbound.received)

        # the outbound node checks in (spec §5)
        status, reply = wait_for(lambda: (lambda r: r if r[0] == 200 else None)(
            outbound.checkin_over_http(url)), 20, step=1)
        assert reply == {"result": "ok"}
        net = wait_for(lambda: (lambda b: b if b["nodes_total"] == 2 else None)(
            http("GET", url + "/v1/network")[1]), 20)
        assert net["nodes_reachable"] == 2

        # new nodes are provisional, so not ranked yet
        status, body = http("GET", url + "/v1/nodes/QmInbound")
        assert (status, body) == (404, {"error": "not_ranked"})

        # attestation for the probed inbound node
        body = {"peer_id": "QmInbound", "service_pubkey": inbound.service_pubkey, "network": "testnet",
                "stake": STAKE,
                "binding_sig": ping.sign(sk(1), ping.binding_message("QmInbound", inbound.service_pubkey,
                                                                     "testnet"))}
        status, att2 = http("POST", url + "/v1/attest", body)
        assert status == 200 and csrchain.verify_attestation_v2(att2, mon_pk)
        assert att2["version"] == 2 and att2["stake"] == STAKE
        assert att2["monitor_pubkey"] == mon_pk and att2["network_id"] == 1

        # the clock of the config cell is kept current
        wait_for(lambda: clock_txs, 20)
        data_out = from_hex(clock_txs[0]["outputs_data"][0])
        assert csrchain.parse_config_cell(data_out)["clock_ms"] > 1_000

        # the registry cell is read
        def registered():
            con = sqlite3.connect(str(data / "t.db"))
            rows = con.execute("select peer_id, expiry_ms from registrations").fetchall()
            con.close()
            return rows
        assert wait_for(registered, 20) == [("QmInbound", 1_900_000_000_000)]

        # the node goes away: the daemon keeps running
        rpc.__exit__()
        rpc = None
        time.sleep(3)
        assert proc.poll() is None
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
        try:
            code = proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
        out, err = proc.communicate()
        inbound.__exit__()
        if rpc is not None:
            rpc.__exit__()
    assert code == 0, err[-3000:]
