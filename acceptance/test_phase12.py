"""Phase 12 acceptance: CLI, daemon wiring, packaging and documentation, end to end."""
import json
import os
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request

import pytest

from csrmon import config as config_mod, crypto, protocol, store as store_mod
from csrmon.hashing import blake160, to_hex
from fakes import FakeChain, FakeRpcServer, FakeRunner, make_registration_cell, block_hash, REG_CODE_HASH

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def sk(n):
    return n.to_bytes(32, "big")


def cli(*args, timeout=60):
    return subprocess.run([sys.executable, "-m", "csrmon", *args], cwd=ROOT, capture_output=True,
                          text=True, timeout=timeout)


def write_cfg(tmp_path, **extra):
    base = {"network": '"testnet"', "public_url": '"https://m.example"',
            "db_path": f'"{tmp_path}/data/t.db"', "key_path": f'"{tmp_path}/data/k.key"'}
    base.update(extra)
    p = tmp_path / "monitor.toml"
    p.write_text("".join(f"{k} = {v}\n" for k, v in base.items()))
    return str(p)


# ---------- CLI ----------

def test_check_config(tmp_path):
    good = write_cfg(tmp_path)
    r = cli("check-config", "--config", good)
    assert r.returncode == 0 and "ok" in r.stdout
    bad = write_cfg(tmp_path, node_rpc='"http://10.0.0.5:8114"')
    r = cli("check-config", "--config", bad)
    assert r.returncode == 2 and r.stderr.strip()


def test_keygen_show_key_init_db(tmp_path):
    cfg = write_cfg(tmp_path)
    r = cli("show-key", "--config", cfg)
    assert r.returncode == 1                      # no key yet
    r = cli("keygen", "--config", cfg)
    assert r.returncode == 0
    info = json.loads(r.stdout)
    key_file = tmp_path / "data" / "k.key"
    assert stat.S_IMODE(os.stat(key_file).st_mode) == 0o600
    secret = bytes.fromhex(key_file.read_text().strip()[2:])
    pk = crypto.pubkey_from_secret(secret)
    assert info == {"pubkey": to_hex(pk), "blake160": to_hex(blake160(pk))}
    assert json.loads(cli("keygen", "--config", cfg).stdout) == info   # existing key kept
    assert json.loads(cli("show-key", "--config", cfg).stdout) == info
    r = cli("init-db", "--config", cfg)
    assert r.returncode == 0
    st = store_mod.Store(str(tmp_path / "data" / "t.db"))
    start = int(st.get_meta("monitor_start"))
    assert abs(start - time.time()) < 120
    st.close()
    cli("init-db", "--config", cfg)
    st = store_mod.Store(str(tmp_path / "data" / "t.db"))
    assert int(st.get_meta("monitor_start")) == start           # never moved
    st.close()


def test_usage_errors():
    assert cli().returncode != 0
    assert cli("frobnicate").returncode != 0


# ---------- packaging and docs ----------

REQUIRED_FILES = ["README.md", "LICENSE", "pyproject.toml", "docs/PROTOCOL.md", "docs/INSTALL.md",
                  "docs/P2P_HELPER.md", "config/monitor-testnet.toml", "config/monitor-mainnet.toml",
                  "deploy/csr-network-monitor@.service", "deploy/Dockerfile",
                  "deploy/Caddyfile.example"]


def read(rel):
    return open(os.path.join(ROOT, rel), encoding="utf-8").read()


def test_files_exist():
    for f in REQUIRED_FILES:
        assert os.path.isfile(os.path.join(ROOT, f)), f


def test_pyproject():
    p = tomllib.loads(read("pyproject.toml"))
    proj = p["project"]
    assert proj["name"] == "csr-network-monitor" and proj["version"] == "0.1.0"
    assert proj.get("dependencies", []) == []
    assert proj["scripts"]["csrmon"] == "csrmon.cli:main"
    assert "3.11" in proj["requires-python"]


def test_example_configs():
    for net in ("testnet", "mainnet"):
        c = config_mod.load_config(os.path.join(ROOT, f"config/monitor-{net}.toml"))
        assert c.network == net
        assert c.node_rpc.startswith("http://127.0.0.1:")
        assert c.db_path != "" and c.key_path != ""
    t = config_mod.load_config(os.path.join(ROOT, "config/monitor-testnet.toml"))
    m = config_mod.load_config(os.path.join(ROOT, "config/monitor-mainnet.toml"))
    assert t.db_path != m.db_path and t.key_path != m.key_path and t.listen_port != m.listen_port


def test_service_unit_and_docker():
    unit = read("deploy/csr-network-monitor@.service")
    assert re.search(r"^ExecStart=.*-m csrmon run --config \S*monitor-%i\.toml", unit, re.M)
    assert re.search(r"^Restart=on-failure", unit, re.M)
    assert re.search(r"^User=\S+", unit, re.M)
    assert re.search(r"^WantedBy=multi-user\.target", unit, re.M)
    docker = read("deploy/Dockerfile")
    assert re.search(r"^FROM python:3\.1[1-9]", docker, re.M)
    assert "csrmon" in docker and "run" in docker
    caddy = read("deploy/Caddyfile.example")
    assert "reverse_proxy" in caddy and "/v1/testnet" in caddy and "/v1/mainnet" in caddy


def test_docs():
    proto = read("docs/PROTOCOL.md")
    for s in ("CSR/v1/challenge", "CSR/v1/probe", "CSR/v1/bind", "CSR/v1/checkin", "CSR/v1/epoch",
              "/csr/v1/probe", "/v1/{network}/checkin", "/v1/{network}/checkin/response",
              "ckb-default-hash", "registration", "canonical"):
        assert s in proto, s
    install = read("docs/INSTALL.md").lower()
    for s in ("wireguard", "nftables", "dnat", "snat", "fwmark", "systemd", "keygen", "geolite2",
              "db-ip"):
        assert s in install, s
    helper = read("docs/P2P_HELPER.md")
    for s in ("peer_id_seen", "heights", "served", "latency_ms", "timeout_s", "address"):
        assert s in helper, s
    readme = read("README.md").lower()
    assert "pytest" in readme and "csrmon" in readme and "reputation source" in readme


# ---------- end to end ----------

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def http(method, url, obj=None, timeout=5):
    data = json.dumps(obj).encode() if obj is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"null")


def wait_for(fn, timeout, step=0.3):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = fn()
            if last:
                return last
        except Exception as e:      # noqa: BLE001
            last = e
        time.sleep(step)
    raise AssertionError(f"timed out, last={last!r}")


def test_end_to_end(tmp_path):
    fc = FakeChain(tip=90_000)
    runner = FakeRunner(sk(1), sk(101), fc)
    runner.__enter__()
    c_pull, reg_pull = make_registration_cell(sk(1), sk(101), endpoint=runner.url, tx_byte=1)
    c_push, reg_push = make_registration_cell(sk(2), sk(102), mode="push", endpoint="",
                                              p2p_port=0, tx_byte=2)
    fc.cells = [c_pull, c_push]
    rpc = FakeRpcServer(fc)
    rpc.__enter__()
    rpc_open = [True]
    port = free_port()
    cfg = write_cfg(tmp_path, node_rpc=f'"{rpc.url}"', listen_port=port, probe_interval_s=3,
                    probe_jitter_s=0, probe_timeout_s=2, aggregate_interval_s=1,
                    registration_code_hash=f'"{REG_CODE_HASH}"', allow_insecure_endpoints="true")
    proc = subprocess.Popen([sys.executable, "-m", "csrmon", "run", "--config", cfg], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    base = f"http://127.0.0.1:{port}"
    try:
        mon = wait_for(lambda: http("GET", base + "/v1/monitor")[1], 30)
        assert mon["network"] == "testnet" and mon["tip"]["number"] == 90_000

        def pull_ok():
            s, d = http("GET", f"{base}/v1/testnet/runners/{reg_pull.runner_id}")
            return s == 200 and d["last_probe"] and d["last_probe"]["result"] == "ok" and d
        wait_for(pull_ok, 40)
        assert any(path == "/csr/v1/probe" for path, _ in runner.received)

        def push_ok():
            s, body = http("POST", base + "/v1/testnet/checkin",
                           protocol.make_checkin(sk(2), "testnet", int(time.time())))
            if s != 200:
                return False
            ch = body["challenge"]
            tip = fc.tip_number - 1
            resp = protocol.sign_response(
                sk(2), ch, peer_id=reg_push.peer_id, tip_number=tip, tip_hash=block_hash(tip),
                block_hash=block_hash(ch["block_height"]), ibd=False, peers_out=8,
                csr_version="0.1.0", ckb_version="0.203.0")
            s, res = http("POST", base + "/v1/testnet/checkin/response",
                          {"runner_id": reg_push.runner_id, "response": resp})
            return s == 200 and res["result"] == "ok"
        wait_for(push_ok, 20, step=1)

        def aggregated():
            s, h = http("GET", f"{base}/v1/testnet/runners/{reg_pull.runner_id}/history?bucket=day")
            return s == 200 and h["items"] and h["items"][-1]["probes_ok"] >= 1
        wait_for(aggregated, 30)

        s, summary = http("GET", base + "/v1/testnet/summary")
        assert s == 200 and summary["provisional_count"] == 2 and summary["runner_count"] == 0

        with urllib.request.urlopen(base + "/", timeout=5) as r:
            assert r.status == 200 and b'id="ranking"' in r.read()

        # the node goes away: the daemon must keep running and report it
        rpc.__exit__()
        rpc_open[0] = False
        time.sleep(4)
        assert proc.poll() is None
        mon = http("GET", base + "/v1/monitor")[1]
        assert mon["tip"] is None
    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
        try:
            code = proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise
        out, err = proc.communicate()
        runner.__exit__()
        if rpc_open[0]:
            rpc.__exit__()
    assert code == 0, err[-3000:]
