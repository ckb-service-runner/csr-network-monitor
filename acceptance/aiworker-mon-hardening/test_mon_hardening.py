"""mon-hardening: signing library, HTTP server limits, safe outgoing requests, headers, rate limits, privacy."""
import hashlib
import http.server
import json
import os
import socket
import sqlite3
import stat
import threading
import time

import pytest

from csrmon import api as api_mod, config as config_mod, crypto, discovery, store as store_mod

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MON = (0x51).to_bytes(32, "big")
NOW = 1_792_281_600

VECTORS = [
    (0x51, "7b4ec2e725b3a6ea95445151f31066771c1e5b9067b29a0605dad5d5871eff70"
           "6275f642a804274924692ce036a1f1807f0972c27d1aa607f2311e5f8ebe1bd800"),
    (0x1234, "59a61b396c9e8a3b5b13f17fb0fe5465b06162e47d56497b215ad6b15e509dee"
             "0cc3e82d1bea1ab8a3946b40263b25c703ca3e448034ee99334dc750d617835600"),
]


def make_config(tmp_path, **extra):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    for k, v in extra.items():
        lines.append(f"{k} = {json.dumps(v)}")
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    return config_mod.load_config(str(tmp_path / "c.toml"))


@pytest.fixture
def env(tmp_path):
    c = make_config(tmp_path, rate_limit_post_per_min=2)
    st = store_mod.Store(c.db_path)
    return {"c": c, "st": st, "api": api_mod.Api(st, c, MON, clock=lambda: NOW), "tmp": tmp_path}


# ---- F-SEC-005: constant-time signing through libsecp256k1 (decision D27 A) ----

def test_signing_uses_libsecp256k1(monkeypatch):
    assert crypto.BACKEND == "libsecp256k1"
    monkeypatch.setattr(crypto, "_mul", lambda *a: (_ for _ in ()).throw(AssertionError("pure-Python multiply used")))
    for n, want in VECTORS:
        msg = hashlib.sha256(b"csr-vector-%d" % n).digest()
        assert crypto.sign(n.to_bytes(32, "big"), msg).hex() == want


def test_signatures_still_recover():
    for n, want in VECTORS:
        msg = hashlib.sha256(b"csr-vector-%d" % n).digest()
        assert crypto.recover(msg, bytes.fromhex(want)) == crypto.pubkey_from_secret(n.to_bytes(32, "big"))


def test_coincurve_is_a_declared_dependency():
    text = open(os.path.join(ROOT, "pyproject.toml")).read()
    assert "coincurve" in text


# ---- F-SEC-006: server timeout and connection cap ----

def _server(env, **kw):
    srv = api_mod.ApiServer(env["api"], "127.0.0.1", 0, **kw)
    srv.start()
    return srv


def _closed_within(sock, seconds):
    sock.settimeout(seconds)
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                return True
    except (socket.timeout, TimeoutError):
        return False
    except ConnectionResetError:
        return True


def test_slow_client_is_dropped(env):
    srv = _server(env, timeout_s=1)
    try:
        s = socket.create_connection(("127.0.0.1", srv.port))
        s.sendall(b"POST /v1/checkin HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\nabc")
        t = time.time()
        assert _closed_within(s, 5), "the server must close a connection that stalls"
        assert time.time() - t < 4.5
        s.close()
    finally:
        srv.stop()


def test_connections_are_capped(env):
    srv = _server(env, timeout_s=5, max_connections=2)
    try:
        held = [socket.create_connection(("127.0.0.1", srv.port)) for _ in range(2)]
        time.sleep(0.3)
        extra = socket.create_connection(("127.0.0.1", srv.port))
        extra.settimeout(3)
        data = b""
        try:
            while True:
                chunk = extra.recv(4096)
                if not chunk:
                    break
                data += chunk
        except (socket.timeout, TimeoutError):
            pytest.fail("a connection over the cap must be refused at once (503 or close)")
        except ConnectionResetError:
            pass
        assert data == b"" or b" 503 " in data.split(b"\r\n")[0]
        for s in held + [extra]:
            s.close()
    finally:
        srv.stop()


# ---- F-SEC-007, F-SEC-017: outgoing requests ----

class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/elsewhere")
            self.send_header("Content-Length", "0")
            self.end_headers()
        elif self.path == "/big":
            self.send_response(200)
            self.send_header("Content-Length", str(1 << 20))
            self.end_headers()
            self.wfile.write(b"x" * (1 << 20))
        else:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

    do_POST = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture
def local_http():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_fetch_reads_small_answers(local_http, monkeypatch):
    from csrmon import netutil
    monkeypatch.setenv("http_proxy", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    assert netutil.fetch(local_http + "/", timeout=5, max_bytes=4096) == b"ok"


def test_fetch_refuses_redirects(local_http):
    from csrmon import netutil
    with pytest.raises(netutil.FetchError):
        netutil.fetch(local_http + "/redirect", timeout=5, max_bytes=4096)


def test_fetch_limits_the_answer(local_http):
    from csrmon import netutil
    with pytest.raises(netutil.FetchError):
        netutil.fetch(local_http + "/big", timeout=5, max_bytes=4096)


def test_public_ip_rule():
    from csrmon import netutil
    for ip in ("10.1.2.3", "127.0.0.1", "169.254.1.1", "192.168.1.5", "172.16.0.1", "::1", "fc00::1", "fe80::1",
               "0.0.0.0", "100.64.0.1"):
        assert not netutil.public_ip(ip), ip
    for ip in ("8.8.8.8", "2a00:1450:4001::1"):
        assert netutil.public_ip(ip), ip


def test_discovery_skips_private_peers(tmp_path):
    peers = [{"node_id": "QmPriv", "ip": "10.0.0.7"}, {"node_id": "QmPub", "ip": "8.8.4.4"}]
    c = make_config(tmp_path)
    st = store_mod.Store(c.db_path)
    got = {p["node_id"] for p in discovery.Discovery(st, c).due(peers, NOW)}
    assert got == {"QmPub"}
    c2 = make_config(tmp_path / ".." / tmp_path.name, allow_insecure_endpoints=True)
    got = {p["node_id"] for p in discovery.Discovery(st, c2).due(peers, NOW)}
    assert got == {"QmPriv", "QmPub"}


# ---- F-SEC-012: no growing schedule maps ----

def test_planned_time_is_stateless():
    from csrmon import schedule
    a = schedule.planned_time(b"k" * 32, "r1", 7, 600, 60)
    assert a == schedule.planned_time(b"k" * 32, "r1", 7, 600, 60)
    assert 7 * 600 <= a < 8 * 600
    assert abs(a - (7 * 600 + 300)) <= 60
    others = {schedule.planned_time(b"k" * 32, f"r{i}", 7, 600, 60) for i in range(50)}
    assert len(others) > 40, "different runners get different times"


# ---- F-SEC-013: headers ----

def test_static_and_json_headers(env):
    status, h, _ = env["api"].handle("GET", "/", {}, b"", "127.0.0.1")
    assert status == 200
    h = {k.lower(): v for k, v in h.items()}
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert "default-src 'self'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff"
    status, h, _ = env["api"].handle("GET", "/v1/monitor", {}, b"", "127.0.0.1")
    assert {k.lower(): v for k, v in h.items()}["x-content-type-options"] == "nosniff"


# ---- F-MON-016: POST rate limit ----

def test_post_routes_are_rate_limited(env):
    codes = [env["api"].handle("POST", "/v1/checkin", {}, b"{}", "203.0.113.9")[0] for _ in range(3)]
    assert codes[2] == 429, codes
    assert codes[0] != 429
    other = env["api"].handle("POST", "/v1/attest", {}, b"{}", "203.0.113.10")[0]
    assert other != 429, "the limit is per client"


# ---- F-MON-015: privacy of the database ----

def test_discovery_stores_no_raw_ip(env):
    st = env["st"]
    st.discovery_mark("198.51.100.23", "QmX", ts=NOW, ok=False)
    assert st.discovery_get("198.51.100.23")["node_id"] == "QmX"
    con = sqlite3.connect(env["c"].db_path)
    rows = con.execute("select * from discovery").fetchall()
    con.close()
    assert rows and all("198.51.100.23" not in str(r) for r in rows)


def test_database_file_is_private(env):
    mode = stat.S_IMODE(os.stat(env["c"].db_path).st_mode)
    assert mode & 0o077 == 0, oct(mode)


# ---- wiring ----

def test_no_direct_urlopen_outside_netutil():
    for name in ("chain.py", "csrprobe.py", "discovery.py", "prober.py", "p2p.py"):
        p = os.path.join(ROOT, "csrmon", name)
        if os.path.exists(p):
            assert "urlopen(" not in open(p).read(), name


def test_no_planned_maps_left():
    for name in ("csrprobe.py", "prober.py", "p2p.py"):
        p = os.path.join(ROOT, "csrmon", name)
        if os.path.exists(p):
            assert "_planned" not in open(p).read(), name


def test_docs_cover_proxies_and_limits():
    install = open(os.path.join(ROOT, "docs", "INSTALL.md")).read()
    assert "trusted_proxies" in install and "Docker" in install
    proto = open(os.path.join(ROOT, "docs", "PROTOCOL.md")).read()
    assert "rate_limit_post_per_min" in proto
