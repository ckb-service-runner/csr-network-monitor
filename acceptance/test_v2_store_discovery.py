"""v2 Phase 4 acceptance: new config keys, store additions, P2P peer discovery."""
import sqlite3
import textwrap

import pytest

from csrmon import config as config_mod, store as store_mod, discovery, chain as chain_mod
from fakes import FakeRpcServer
from fakes_v2 import FakeChainV2, peer_entry

T0 = 1792281600


def cfg(tmp_path, extra=""):
    p = tmp_path / "c.toml"
    p.write_text(textwrap.dedent(f"""
        network = "testnet"
        public_url = "https://monitor-testnet.vericell.net"
        db_path = "{tmp_path}/t.db"
        key_path = "{tmp_path}/k.key"
    """) + extra)
    return config_mod.load_config(str(p))


def test_new_config_defaults(tmp_path):
    c = cfg(tmp_path)
    assert c.ping_port == 8131
    assert c.discovery_interval_s == 600
    assert c.discovery_backoff_s == 86400
    assert c.answer_deadline_s == 60
    assert c.reachable_window_s == 3600
    assert c.csr_registry_code_hash == ""
    assert c.csr_registry_hash_type == "data2"
    assert c.config_type_args == ""
    assert c.clock_update_interval_s == 3600
    assert c.clock_update_fee_shannons == 100000
    assert c.attest_validity_days == 7
    assert c.attest_min_ok_24h == 1
    assert c.attest_cache_s == 3600


def test_new_config_overrides_and_checks(tmp_path):
    c = cfg(tmp_path, 'ping_port = 18131\nconfig_type_args = "0x' + "ab" * 32 + '"\n')
    assert c.ping_port == 18131 and c.config_type_args == "0x" + "ab" * 32
    for bad in ('ping_port = 0\n', 'ping_port = 70000\n', 'config_type_args = "0x1234"\n',
                'csr_registry_hash_type = "foo"\n', 'attest_validity_days = 0\n'):
        with pytest.raises(config_mod.ConfigError):
            cfg(tmp_path, bad)


def rid(n):
    return "0x" + f"{n:064x}"


def add(st, n, peer, now=T0, mode="inbound", endpoint="http://1.2.3.4:8131"):
    st.upsert_runner(rid(n), service_pubkey="0x02" + f"{n:02x}" * 32, peer_id=peer, p2p_pubkey="",
                     reg_outpoint="", mode=mode, endpoint=endpoint, p2p_port=0,
                     ranking_opt_in=True, now=now)


def test_probe_p2p_verified_and_migration(tmp_path):
    path = str(tmp_path / "t.db")
    st = store_mod.Store(path)
    add(st, 1, "QmA")
    st.record_probe(rid(1), ts=T0, slot=1, mode="inbound", result="ok", p2p_verified=True)
    st.record_probe(rid(1), ts=T0 + 600, slot=2, mode="inbound", result="ok")
    rows = st.probes(rid(1))
    assert rows[0]["p2p_verified"] is True and rows[1]["p2p_verified"] is None
    st.close()
    con = sqlite3.connect(path)
    con.execute("ALTER TABLE probes DROP COLUMN p2p_verified")   # a database written by v1
    con.commit()
    con.close()
    st = store_mod.Store(path)                                   # migrates on open
    assert [p["slot"] for p in st.probes(rid(1))] == [1, 2]
    st.record_probe(rid(1), ts=T0 + 1200, slot=3, mode="outbound", result="ok", p2p_verified=False)
    assert st.probes(rid(1))[-1]["p2p_verified"] is False
    st.close()


def test_find_runner_by_peer(tmp_path):
    st = store_mod.Store(str(tmp_path / "t.db"))
    add(st, 1, "QmA", now=T0)
    add(st, 2, "QmA", now=T0 + 100)
    add(st, 3, "QmB")
    st.record_probe(rid(1), ts=T0 + 500, slot=1, mode="inbound", result="ok")
    assert st.find_runner_by_peer("QmA")["runner_id"] == rid(1)     # most recently seen
    st.set_status(rid(1), "deregistered")
    assert st.find_runner_by_peer("QmA")["runner_id"] == rid(2)
    assert st.find_runner_by_peer("QmZ") is None
    st.close()


def test_registrations_and_issued(tmp_path):
    st = store_mod.Store(str(tmp_path / "t.db"))
    st.set_registrations([
        {"peer_id": "QmA", "service_pubkey": "0x02aa", "expiry_ms": 5000, "outpoint": "0x01:0"},
        {"peer_id": "QmA", "service_pubkey": "0x02aa", "expiry_ms": 9000, "outpoint": "0x02:0"},
        {"peer_id": "QmB", "service_pubkey": "0x02bb", "expiry_ms": 7000, "outpoint": "0x03:1"},
    ])
    assert st.registration_for("QmA") == {"peer_id": "QmA", "service_pubkey": "0x02aa",
                                          "expiry_ms": 9000, "outpoint": "0x02:0"}
    assert st.registration_for("QmC") is None
    st.set_registrations([{"peer_id": "QmB", "service_pubkey": "0x02bb", "expiry_ms": 1, "outpoint": "x"}])
    assert st.registration_for("QmA") is None            # replaced as a whole
    assert st.last_issued("QmA", "0x02aa") is None
    st.save_issued("QmA", "0x02aa", issued_at=100, attestation={"expiry_ms": 1, "x": [1]})
    st.save_issued("QmA", "0x02aa", issued_at=200, attestation={"expiry_ms": 2})
    assert st.last_issued("QmA", "0x02aa") == {"issued_at": 200, "attestation": {"expiry_ms": 2}}
    st.close()


def test_discovery_table(tmp_path):
    st = store_mod.Store(str(tmp_path / "t.db"))
    assert st.discovery_get("1.2.3.4") is None
    st.discovery_mark("1.2.3.4", "QmA", ts=100, ok=False)
    assert st.discovery_get("1.2.3.4") == {"ip": "1.2.3.4", "node_id": "QmA", "last_try": 100, "last_ok": None}
    st.discovery_mark("1.2.3.4", "QmA", ts=200, ok=True)
    st.discovery_mark("1.2.3.4", "QmA", ts=300, ok=False)
    assert st.discovery_get("1.2.3.4") == {"ip": "1.2.3.4", "node_id": "QmA", "last_try": 300, "last_ok": 200}
    st.close()


# ---------- discovery ----------

RAW_PEERS = [
    peer_entry("QmA", ["/ip4/1.2.3.4/tcp/8115/p2p/QmA"]),
    peer_entry("QmB", ["/dns4/node.example/tcp/8115", "/ip6/2001:db8::7/tcp/8115/p2p/QmB"]),
    peer_entry("QmC", ["/dns4/only.example/tcp/8115"]),
    peer_entry("QmA", ["/ip4/9.9.9.9/tcp/8115"]),            # duplicate node id
    {"node_id": "QmD", "addresses": []},
]


def test_parse_peers():
    assert discovery.parse_peers(RAW_PEERS) == [
        {"node_id": "QmA", "ip": "1.2.3.4"},
        {"node_id": "QmB", "ip": "2001:db8::7"},
    ]
    assert discovery.parse_peers([]) == []
    assert discovery.parse_peers([{"junk": 1}]) == []


def test_endpoint_for():
    assert discovery.endpoint_for("1.2.3.4", 8131) == "http://1.2.3.4:8131"
    assert discovery.endpoint_for("2001:db8::7", 8131) == "http://[2001:db8::7]:8131"


def test_get_peers_rpc():
    fc = FakeChainV2(tip=1000)
    fc.peers = RAW_PEERS
    with FakeRpcServerV2(fc) as srv:
        assert chain_mod.RpcChain(srv.url).get_peers() == RAW_PEERS


class FakeRpcServerV2(FakeRpcServer):
    def dispatch(self, method, params):
        if method == "get_peers":
            return self.chain.peers
        return super().dispatch(method, params)


def test_discovery_due(tmp_path):
    c = cfg(tmp_path, "ping_port = 18131\n")
    st = store_mod.Store(c.db_path)
    d = discovery.Discovery(st, c)
    peers = discovery.parse_peers(RAW_PEERS)
    assert d.due(peers, now=T0) == [
        {"node_id": "QmA", "ip": "1.2.3.4", "endpoint": "http://1.2.3.4:18131"},
        {"node_id": "QmB", "ip": "2001:db8::7", "endpoint": "http://[2001:db8::7]:18131"},
    ]
    st.discovery_mark("1.2.3.4", "QmA", ts=T0, ok=False)
    assert [p["node_id"] for p in d.due(peers, now=T0 + 10)] == ["QmB"]           # backed off
    assert [p["node_id"] for p in d.due(peers, now=T0 + 86401)] == ["QmA", "QmB"]  # backoff over
    add(st, 7, "QmB", endpoint="http://[2001:db8::7]:18131")                     # already a runner
    assert [p["node_id"] for p in d.due(peers, now=T0 + 86401)] == ["QmA"]
    st.set_status(rid(7), "deregistered")
    assert [p["node_id"] for p in d.due(peers, now=T0 + 86401)] == ["QmA", "QmB"]
    st.close()
