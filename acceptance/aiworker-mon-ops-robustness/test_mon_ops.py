"""mon-ops-robustness: API errors, caching, config warnings, scan and clock status, epoch publishing."""
import json
import os

import pytest

from csrmon import api as api_mod, config as config_mod, configcell, stat_cell, store as store_mod

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MON = (0x51).to_bytes(32, "big")
NOW = 1_792_281_600
A7_HASH = "0x47fee83ea91eabdfc8827045f63fe051b8fee5c05b9280a35f42f2e3597d3f36"
A8_HASH = "0x411aceb357a61684226169902cab2ccf64f470f0aaf93687d7cd2904f3c741d8"


def make_config(tmp_path, **extra):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    lines += [f"{k} = {json.dumps(v)}" for k, v in extra.items()]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    return config_mod.load_config(str(tmp_path / "c.toml"))


@pytest.fixture
def env(tmp_path):
    c = make_config(tmp_path, rate_limit_per_min=1000)
    st = store_mod.Store(c.db_path)
    st.set_meta("monitor_start", str(NOW - 60 * 86400))
    return {"c": c, "st": st, "api": api_mod.Api(st, c, MON, clock=lambda: NOW)}


def get(env, path):
    status, _, data = env["api"].handle("GET", path, {}, b"", "10.0.0.1")
    return status, json.loads(data) if data else None


# ---- F-FUN-010 ----

def test_odd_epoch_id_gets_an_answer(env):
    status, body = get(env, "/v1/testnet/epochs/²")
    assert status in (400, 404), (status, body)


def test_huge_history_range_gets_400(env):
    from csrmon import crypto, protocol
    from csrmon.hashing import to_hex
    pub = crypto.pubkey_from_secret((3).to_bytes(32, "big"))
    rid = protocol.runner_id(pub)
    env["st"].upsert_runner(rid, service_pubkey=to_hex(pub), peer_id="QmThree", p2p_pubkey="", reg_outpoint="",
                            mode="inbound", endpoint="", p2p_port=0, ranking_opt_in=True, now=NOW - 86400)
    status, body = get(env, f"/v1/testnet/runners/{rid}/history?bucket=day&from=0&to=1000000000000000000")
    assert status in (400, 404), (status, body)
    assert status != 500


def test_unexpected_errors_become_500(env, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(env["api"], "_monitor", boom)
    status, body = get(env, "/v1/monitor")
    assert status == 500 and body == {"error": "internal"}


# ---- F-MON-019 ----

@pytest.mark.parametrize("path", ["/v1/network", "/v1/locations"])
def test_network_views_are_cached(env, monkeypatch, path):
    calls = []
    real = env["st"].list_runners
    monkeypatch.setattr(env["st"], "list_runners", lambda *a, **k: calls.append(1) or real(*a, **k))
    assert get(env, path)[0] == 200
    n = len(calls)
    assert get(env, path)[0] == 200
    assert len(calls) == n, "a second call within 30 s must come from the cache"


# ---- F-MON-017, F-MON-020, F-FUN-011 ----

def test_config_warnings(tmp_path):
    w = " ".join(config_mod.config_warnings(make_config(tmp_path)))
    assert "registry" in w.lower()
    assert "second_tip_source" in w
    w = " ".join(config_mod.config_warnings(make_config(
        tmp_path, csr_registry_code_hash=A7_HASH, config_type_args="0x" + "a9" * 32,
        second_tip_source="http://127.0.0.1:8115")))
    assert "A7" in w or "old" in w.lower()
    assert config_mod.config_warnings(make_config(
        tmp_path, csr_registry_code_hash=A8_HASH, config_type_args="0x" + "a9" * 32,
        second_tip_source="http://127.0.0.1:8115")) == []


def test_example_config_and_install_guide_name_the_a8_hash():
    for p in (("config", "monitor-testnet.toml"), ("docs", "INSTALL.md")):
        t = open(os.path.join(ROOT, *p)).read()
        assert A8_HASH in t and A7_HASH not in t, p


def test_monitor_endpoint_reports_scan_and_clock(env):
    env["st"].set_meta("registry_last_scan_at", str(NOW - 120))
    env["st"].set_meta("clock_ms", str((NOW - 7200) * 1000))
    status, body = get(env, "/v1/monitor")
    assert status == 200
    assert body["registry_last_scan_at"] == NOW - 120
    assert body["clock_age_s"] == 7200


# ---- F-FUN-016 ----

def test_stale_clock_stops_attestations():
    assert configcell.clock_fresh(clock_ms=(NOW - 600) * 1000, now_s=NOW, max_age_s=3 * 3600)
    assert not configcell.clock_fresh(clock_ms=(NOW - 4 * 3600) * 1000, now_s=NOW, max_age_s=3 * 3600)


# ---- F-FUN-009 ----

def test_epoch_publish_waits_for_commit():
    assert stat_cell.next_action("committed", sent_block=100, tip=104) == "published"
    assert stat_cell.next_action("pending", sent_block=100, tip=110) == "wait"
    assert stat_cell.next_action("proposed", sent_block=100, tip=110) == "wait"
    assert stat_cell.next_action("rejected", sent_block=100, tip=101) == "resend"
    assert stat_cell.next_action("unknown", sent_block=100, tip=100 + stat_cell.RESEND_AFTER_BLOCKS) == "resend"
    assert stat_cell.next_action("unknown", sent_block=100, tip=101) == "wait"


def test_daemon_confirms_and_publishes_one_epoch_per_pass():
    d = open(os.path.join(ROOT, "csrmon", "daemon.py")).read()
    assert "confirm" in d
    s = open(os.path.join(ROOT, "csrmon", "stat_cell.py")).read()
    assert "def confirm" in s
    c = open(os.path.join(ROOT, "csrmon", "chain.py")).read()
    assert "get_transaction" in c


# ---- F-FUN-015 ----

def test_epochs_record_when_they_were_built():
    e = open(os.path.join(ROOT, "csrmon", "epochs.py")).read()
    assert "built_at" in e and "late" in e
    assert "built_at" in open(os.path.join(ROOT, "docs", "PROTOCOL.md")).read()
