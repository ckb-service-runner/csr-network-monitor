"""monitor-v3 wiring: lifetime cap, config keys, csr-config-type clock update, endpoints (F-MON-014)."""
import json
import random
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from csrmon import api as api_mod, configcell, crypto, csrchain, csrprobe, discovery, molecule, ping, protocol
from csrmon import prober as prober_mod, store as store_mod, config as config_mod
from csrmon.hashing import blake160, from_hex, to_hex
from fakes import cell, block_ts
from fakes_stake import FakeChainStake, dao_live, dual_lock, sk
from fakes_v2 import FakeCSR
from fakes_v3 import CONFIG_CODE, CONFIG_LINES, config_type, registry_type, registry_v3_data

MON = (0x51).to_bytes(32, "big")
MON_PK_B = crypto.pubkey_from_secret(MON)
MON_PK = to_hex(MON_PK_B)
SIGHASH = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
CONFIG_ARGS = "0x" + "a9" * 32
REGISTRY_CODE = "0x" + "47" * 32
NOW = 1_792_281_600
DAY_MS = 86_400_000
STAKE = "0x" + "5e" * 32 + ":1"
PUBLIC_EP = "https://8.8.8.8:8131"


def pk(n):
    return to_hex(crypto.pubkey_from_secret(sk(n)))


def load(tmp_path, *extra, name="c"):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/{name}.db"', f'key_path = "{tmp_path}/k.key"',
             f'config_type_args = "{CONFIG_ARGS}"', f'csr_registry_code_hash = "{REGISTRY_CODE}"',
             f'stat_cell_sighash_dep_tx = "0x{"5d" * 32}"', "probe_interval_s = 600", "probe_jitter_s = 0",
             *CONFIG_LINES, *extra]
    (tmp_path / f"{name}.toml").write_text("\n".join(lines) + "\n")
    return config_mod.load_config(str(tmp_path / f"{name}.toml"))


@pytest.fixture
def env(tmp_path):
    c = load(tmp_path)
    return {"c": c, "st": store_mod.Store(c.db_path), "fc": FakeChainStake(tip=12_000_000), "tmp": tmp_path}


def add_config_cell(fc, clock_ms, data=None):
    lock = {"code_hash": SIGHASH, "hash_type": "type", "args": to_hex(blake160(MON_PK_B))}
    fc.cells.append(cell(config_type(CONFIG_ARGS), data or to_hex(csrchain.config_cell_data(MON_PK_B, clock_ms)),
                         "0x" + "c0" * 32, 0, capacity=10_000 * 10 ** 8, lock=lock))


def reg_cell(peer, n, stake, *, endpoint="", tx_byte=1):
    t = registry_type(REGISTRY_CODE, CONFIG_ARGS)
    data = registry_v3_data(MON, peer=peer, service_pubkey=pk(n), stake=stake, endpoint=endpoint,
                            expiry_ms=NOW * 1000 + 7 * DAY_MS, type_hash=molecule.script_hash(t))
    return cell(t, data, "0x" + f"{tx_byte:02x}" * 32, 0, lock=dual_lock(n))


# ---------- config ----------

def test_config_keys(tmp_path):
    c = load(tmp_path)
    assert c.config_type_code_hash == CONFIG_CODE and c.config_type_hash_type == "data2"
    assert c.config_type_dep_index == 0
    for bad in ("attest_validity_days = 8", 'config_type_hash_type = "foo"', 'config_type_code_hash = "0x12"',
                'config_type_dep_tx = "0x12"', "config_type_dep_index = -1"):
        with pytest.raises(config_mod.ConfigError):
            load(tmp_path, bad, name="bad")
    assert load(tmp_path, "attest_validity_days = 7", name="ok").attest_validity_days == 7


def test_not_configured_without_code_hash(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m"', f'db_path = "{tmp_path}/t.db"',
             f'key_path = "{tmp_path}/k.key"', f'config_type_args = "{CONFIG_ARGS}"',
             f'csr_registry_code_hash = "{REGISTRY_CODE}"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    assert not configcell.configured(c) and configcell.config_hash_of(c) is None
    assert configcell.registry_hash_of(c) is None
    assert configcell.scan_registry(store_mod.Store(c.db_path), FakeChainStake(), c, MON_PK) is None


# ---------- lifetime cap (D24 A) ----------

def test_lifetime_cap():
    assert configcell.MAX_LIFETIME_MS == 8 * DAY_MS - 3_600_000
    assert configcell.attest_expiry_ms(1000, 7) == 1000 + 7 * DAY_MS
    assert configcell.attest_expiry_ms(1000, 8) == 1000 + 8 * DAY_MS - 3_600_000
    assert configcell.attest_expiry_ms(1000, 30) == 1000 + configcell.MAX_LIFETIME_MS


def eligible(st, n, peer):
    rid = protocol.runner_id(crypto.pubkey_from_secret(sk(n)))
    st.upsert_runner(rid, service_pubkey=pk(n), peer_id=peer, p2p_pubkey="", reg_outpoint="", mode="inbound",
                     endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=True, now=NOW - 3 * 86400)
    st.record_probe(rid, ts=NOW - 600, slot=1000, mode="inbound", result="ok")


def attest_body(n, peer, stake=STAKE):
    p = pk(n)
    return {"peer_id": peer, "service_pubkey": p, "network": "testnet", "stake": stake,
            "binding_sig": ping.sign(sk(n), ping.binding_message(peer, p, "testnet"))}


def test_attest_v2_reply_and_cache_per_stake(env):
    fc, st, c = env["fc"], env["st"], env["c"]
    add_config_cell(fc, NOW * 1000)
    other = "0x" + "5f" * 32 + ":0"
    fc.live[STAKE] = dao_live(1, 10_000)
    fc.live[other] = dao_live(1, 10_000)
    att = configcell.Attester(st, c, MON, configcell.ConfigCellWriter(st, fc, c, MON))
    eligible(st, 1, "QmA")
    status, a1 = att.handle_attest(attest_body(1, "QmA"), "ip", NOW)
    assert status == 200 and a1["version"] == 2 and a1["stake"] == STAKE
    assert a1["registry_type_hash"] == configcell.registry_hash_of(c)
    assert a1["expiry_ms"] - NOW * 1000 <= 8 * DAY_MS
    assert csrchain.verify_attestation_v2(a1, MON_PK)
    for k in ("peer_id", "service_pubkey", "network", "network_id", "expiry_ms", "signature", "monitor_pubkey"):
        assert k in a1, k
    assert att.handle_attest(attest_body(1, "QmA"), "ip", NOW + 5) == (200, a1)
    # another stake is never answered from the cache: the attestation names the stake
    status, a2 = att.handle_attest(attest_body(1, "QmA", other), "ip", NOW + 10)
    assert status == 200 and a2["stake"] == other and a2["signature"] != a1["signature"]


def test_attest_signed_v2_registers(env):
    """The reply of POST /v1/attest makes a Registry v3 cell that the scan accepts."""
    fc, st, c = env["fc"], env["st"], env["c"]
    add_config_cell(fc, NOW * 1000)
    fc.live[STAKE] = dao_live(1, 10_000)
    att = configcell.Attester(st, c, MON, configcell.ConfigCellWriter(st, fc, c, MON))
    eligible(st, 1, "QmA")
    _, a = att.handle_attest(attest_body(1, "QmA"), "ip", NOW)
    reg = {"peer_id": "QmA", "service_pubkey": pk(1), "payout_lock_hash": "0x" + "77" * 32, "network": 1,
           "stake": a["stake"], "expiry_ms": a["expiry_ms"], "attestation_sig": a["signature"],
           "endpoint": "", "prekeys": "0x"}
    fc.cells.append(cell(registry_type(REGISTRY_CODE, CONFIG_ARGS), to_hex(csrchain.encode_registry_v3(reg)),
                         "0x" + "01" * 32, 0, lock=dual_lock(1)))
    assert configcell.scan_registry(st, fc, c, MON_PK) == {"valid": 1, "invalid": 0, "no_stake": 0}


def test_encode_registry_v3_vector():
    import json as _json
    import os
    v = _json.load(open(os.path.join(os.path.dirname(__file__), "aiworker-monitor-v3", "registry-v3.json")))
    for key in ("registry_v3_no_endpoint", "registry_v3_with_endpoint"):
        reg = csrchain.parse_registry_v3(bytes.fromhex(v[key]))
        assert csrchain.encode_registry_v3(reg).hex() == v[key]
        assert len(bytes.fromhex(v[key])) == v[key + "_len"]


# ---------- clock update (csr-config-type) ----------

def test_clock_update_keeps_key_and_never_lowers(env):
    fc, st, c = env["fc"], env["st"], env["c"]
    sent = []
    fc.on_send = lambda tx: (sent.append(tx), molecule.tx_hash(tx))[1]
    data = csrchain.config_cell_data(MON_PK_B, block_ts(11_000_000))
    w = configcell.ConfigCellWriter(st, fc, c, MON)
    add_config_cell(fc, 0, data=to_hex(data))
    assert w.update_clock() is not None
    [tx] = sent
    out = from_hex(tx["outputs_data"][0])
    assert out[:33] == data[:33] and out[41:] == data[41:]
    assert csrchain.parse_config_cell(out)["clock_ms"] == block_ts(12_000_000)
    assert tx["outputs"][0]["type"] == config_type(CONFIG_ARGS)
    assert {"out_point": {"tx_hash": c.config_type_dep_tx, "index": "0x0"}, "dep_type": "code"} in tx["cell_deps"]
    # a clock ahead of the tip is never lowered
    fc.cells = []
    add_config_cell(fc, block_ts(12_000_000) + 1)
    assert w.update_clock() is None and len(sent) == 1


def test_clock_update_requires_config_type_dep(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m"', f'db_path = "{tmp_path}/t.db"',
             f'key_path = "{tmp_path}/k.key"', f'config_type_args = "{CONFIG_ARGS}"',
             f'config_type_code_hash = "{CONFIG_CODE}"', f'stat_cell_sighash_dep_tx = "0x{"5d" * 32}"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    fc = FakeChainStake(tip=12_000_000)
    add_config_cell(fc, 1)
    with pytest.raises(configcell.ConfigCellError):
        configcell.ConfigCellWriter(store_mod.Store(c.db_path), fc, c, MON).update_clock()


# ---------- endpoints (F-MON-014) ----------

def test_endpoint_rules():
    def res(ips):
        return lambda host, port: [(None, None, None, "", (ip, 0)) for ip in ips]

    assert discovery.endpoint_ip("https://8.8.8.8:8131") == "8.8.8.8"
    assert discovery.endpoint_ip("http://[2606:4700::1111]:8131") == "2606:4700::1111"
    assert discovery.endpoint_ip("https://runner.example.org", resolve=res(["1.1.1.1"])) == "1.1.1.1"
    for bad in ("", "ftp://8.8.8.8", "https://10.0.0.1:8131", "http://127.0.0.1:8131", "https://[::1]/",
                "https://192.168.1.5", "https://user:pw@8.8.8.8", "https://8.8.8.8/?x=1", "https://8.8.8.8:99999",
                "https://8.8.8.8 /", "8.8.8.8:8131", None, 5):
        assert discovery.endpoint_ip(bad) is None, bad
    # every resolved address must be public
    assert discovery.endpoint_ip("https://r.example", resolve=res(["1.1.1.1", "10.0.0.1"])) is None
    assert discovery.endpoint_ip("https://10.0.0.1:8131", allow_insecure=True) == "10.0.0.1"

    def fail(host, port):
        raise OSError("nxdomain")
    assert discovery.endpoint_ip("https://nothing.example", resolve=fail) is None


def test_scan_stores_endpoint(env):
    fc, st, c = env["fc"], env["st"], env["c"]
    fc.cells = [reg_cell("QmA", 1, "0x" + "a1" * 32 + ":0", endpoint=PUBLIC_EP, tx_byte=1),
                reg_cell("QmB", 2, "0x" + "a2" * 32 + ":0", tx_byte=2)]
    fc.live["0x" + "a1" * 32 + ":0"] = dao_live(1, 10_000)
    fc.live["0x" + "a2" * 32 + ":0"] = dao_live(2, 10_000)
    assert configcell.scan_registry(st, fc, c, MON_PK)["valid"] == 2
    assert st.registered_endpoints() == [{"peer_id": "QmA", "service_pubkey": pk(1), "endpoint": PUBLIC_EP}]
    assert st.registration_endpoint("QmA", pk(1)) == PUBLIC_EP
    assert st.registration_endpoint("QmB", pk(2)) is None
    assert set(st.registration_for("QmA")) == {"peer_id", "service_pubkey", "expiry_ms", "outpoint"}


def fake_post(nodes, calls):
    def post(url, body, timeout):
        calls.append(url)
        node = nodes.get(url.rsplit("/v1/challenge", 1)[0])
        if node is None:
            raise OSError("unreachable")
        code, out = node.respond(json.loads(body))
        return code, json.dumps(out).encode() if code == 200 else b""
    return post


def test_registered_endpoint_is_probed(env):
    fc, st, c = env["fc"], env["st"], env["c"]
    fc.cells = [reg_cell("QmA", 1, "0x" + "a1" * 32 + ":0", endpoint=PUBLIC_EP)]
    fc.live["0x" + "a1" * 32 + ":0"] = dao_live(1, 10_000)
    configcell.scan_registry(st, fc, c, MON_PK)
    node = FakeCSR(sk(1), "QmA", fc, MON_PK, clock=lambda: NOW)
    calls = []
    p = csrprobe.CsrProber(st, fc, c, MON, clock=lambda: NOW, rng=random.Random(1),
                           http_post=fake_post({PUBLIC_EP: node}, calls))
    d = discovery.Discovery(st, c)
    # not a peer of the monitor's node, still probed at its endpoint
    cands = d.registered(NOW)
    assert [(x["node_id"], x["endpoint"], x["ip"]) for x in cands] == [("QmA", PUBLIC_EP, "8.8.8.8")]
    [res] = p.discover(cands, NOW)
    assert res["result"] == "ok" and calls == [PUBLIC_EP + "/v1/challenge"]
    r = st.get_runner(protocol.runner_id(from_hex(pk(1))))
    assert (r["mode"], r["endpoint"], r["peer_id"]) == ("inbound", PUBLIC_EP, "QmA")
    assert d.registered(NOW + 1) == []          # already probed there
    # the regular pull probe goes to the registered endpoint
    rec = p.probe_inbound(r, NOW + 30)
    assert rec["result"] == "ok" and calls[-1] == PUBLIC_EP + "/v1/challenge"
    # the API shows has_endpoint only, never the raw endpoint
    a = api_mod.Api(st, c, MON, clock=lambda: NOW)
    for path in ("/v1/testnet/runners", "/v1/network", "/v1/monitor"):
        status, _, data = a.handle("GET", path, {}, b"", "10.0.0.1")
        assert "8.8.8.8" not in data.decode(), path


def test_registered_endpoint_must_match_the_registration(env):
    fc, st, c = env["fc"], env["st"], env["c"]
    fc.cells = [reg_cell("QmA", 1, "0x" + "a1" * 32 + ":0", endpoint=PUBLIC_EP)]
    fc.live["0x" + "a1" * 32 + ":0"] = dao_live(1, 10_000)
    configcell.scan_registry(st, fc, c, MON_PK)
    impostor = FakeCSR(sk(2), "QmA", fc, MON_PK, clock=lambda: NOW)     # same peer id, other key
    p = csrprobe.CsrProber(st, fc, c, MON, clock=lambda: NOW, http_post=fake_post({PUBLIC_EP: impostor}, []))
    [res] = p.discover(discovery.Discovery(st, c).registered(NOW), NOW)
    assert (res["result"], res["failure_reason"]) == ("fail", "pubkey_changed")
    assert st.list_runners(None) == []
    # backoff after a failed try
    assert discovery.Discovery(st, c).registered(NOW + 10) == []


def test_private_endpoint_refused_unless_insecure(env, tmp_path):
    fc, st, c = env["fc"], env["st"], env["c"]
    node = FakeCSR(sk(1), "QmA", fc, MON_PK, clock=lambda: NOW)
    fc.cells = [reg_cell("QmA", 1, "0x" + "a1" * 32 + ":0", endpoint=node.url)]     # 127.0.0.1
    fc.live["0x" + "a1" * 32 + ":0"] = dao_live(1, 10_000)
    configcell.scan_registry(st, fc, c, MON_PK)
    assert discovery.Discovery(st, c).registered(NOW) == []
    c2 = load(tmp_path, "allow_insecure_endpoints = true", name="ins")
    st2 = store_mod.Store(c2.db_path)
    configcell.scan_registry(st2, fc, c2, MON_PK)
    with node:
        p = csrprobe.CsrProber(st2, fc, c2, MON, clock=lambda: NOW)
        [res] = p.discover(discovery.Discovery(st2, c2).registered(NOW), NOW)
        assert res["result"] == "ok"
        r = st2.get_runner(protocol.runner_id(from_hex(pk(1))))
        assert r["endpoint"] == node.url
    # the rule is checked again on every probe: without allow_insecure_endpoints the probe is refused
    p = csrprobe.CsrProber(st2, fc, c, MON, clock=lambda: NOW, http_post=lambda *a: pytest.fail("no request"))
    rec = p.probe_inbound(r, NOW + 700)
    assert (rec["result"], rec["failure_reason"]) == ("fail", "endpoint_refused")


def test_redirects_are_not_followed():
    hits = []

    class Target(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        do_GET = do_POST

    target = ThreadingHTTPServer(("127.0.0.1", 0), Target)

    class Redirect(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(307)
            self.send_header("Location", f"http://127.0.0.1:{target.server_address[1]}/v1/challenge")
            self.send_header("Content-Length", "0")
            self.end_headers()

    redir = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    for s in (target, redir):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        status, _ = prober_mod._default_post(f"http://127.0.0.1:{redir.server_address[1]}/v1/challenge", b"{}", 5)
        assert status == 307 and hits == []
    finally:
        for s in (target, redir):
            s.shutdown()
            s.server_close()
