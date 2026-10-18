"""Phase 12 acceptance (v2 version): CLI, packaging, documentation of the CSR-aligned monitor.
The v1 end-to-end test is replaced by test_v2_daemon.py."""
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
    assert "reverse_proxy" in caddy and "monitor-testnet." in caddy
    assert "127.0.0.1:8480" in caddy and "127.0.0.1:8481" in caddy


def test_docs():
    proto = read("docs/PROTOCOL.md")
    for s in ("CSR-PING-CHALLENGE-v1", "CSR-BINDING-v1", "CSR-PING-ANSWER-v1", "CSR-ATTEST-v1",
              "CSR/v1/epoch", "ckb-service-runner", "spec/ping-protocol.md", "spec/registry.md",
              "spec/monitor-public-api.md", "/v1/challenge", "/v1/checkin", "/v1/answer", "/v1/attest",
              "/v1/network", "/v1/nodes/", "ckb-default-hash", "8131", "get_peers", "p2p_verified",
              "clock_ms", "not_eligible"):
        assert s in proto, s
    for gone in ("/csr/v1/probe", "/v1/{network}/checkin", "CSR/v1/challenge"):
        assert gone not in proto, gone
    install = read("docs/INSTALL.md").lower()
    for s in ("wireguard", "nftables", "dnat", "snat", "fwmark", "systemd", "keygen", "geolite2",
              "db-ip", "monitor-testnet.vericell.net", "config_type_args", "csr_registry_code_hash",
              "csr-dev deploy-contracts", "8131"):
        assert s in install, s
    helper = read("docs/P2P_HELPER.md")
    for s in ("peer_id_seen", "heights", "served", "latency_ms", "timeout_s", "address"):
        assert s in helper, s
    readme = read("README.md").lower()
    assert "pytest" in readme and "csrmon" in readme and "reputation source" in readme
