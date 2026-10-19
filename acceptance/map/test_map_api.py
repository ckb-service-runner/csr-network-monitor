"""Map phase 2: GET /v1/locations and its documentation."""
import json
import os
import random

import pytest

from csrmon import api as api_mod, csrprobe, crypto, protocol, store as store_mod, config as config_mod
from csrmon.hashing import to_hex

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MON = (0x51).to_bytes(32, "big")
NOW = 1_792_281_600 + 12 * 3600


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    clock = Clock(NOW)
    api = api_mod.Api(st, c, MON, clock=clock)
    return {"st": st, "api": api, "clock": clock}


def call(env, method, path):
    status, hdrs, data = env["api"].handle(method, path, {}, b"", "10.9.0.1")
    return status, hdrs, (json.loads(data) if data else None)


def add(env, n, *, country="DE", loc=None, opt_in=True, slot=None):
    st = env["st"]
    pub = crypto.pubkey_from_secret(n.to_bytes(32, "big"))
    rid = protocol.runner_id(pub)
    st.upsert_runner(rid, service_pubkey=to_hex(pub), peer_id=f"Qm{n}", p2p_pubkey="", reg_outpoint="",
                     mode="inbound", endpoint="http://1.2.3.4:8131", p2p_port=0, ranking_opt_in=opt_in,
                     now=NOW - 86400)
    kw = {"loc_lat": loc[0], "loc_lon": loc[1]} if loc else {}
    st.record_probe(rid, ts=NOW - 600, slot=slot or n, mode="inbound", result="ok", country=country,
                    asn=3320, **kw)
    return rid


def test_locations(env):
    add(env, 1, country="DE", loc=(53, 13))
    add(env, 2, country="DE", loc=(53, 13))
    add(env, 3, country="DE", loc=(49, 11))
    add(env, 4, country="US", loc=(37, -123))
    add(env, 5, country="US", loc=(41, -75))
    add(env, 6, country="US", loc=(41, -75))
    add(env, 7, country="JP")                       # country known, no location
    add(env, 8, country="??", loc=(1, 1))           # unknown country: never located
    add(env, 9, country="FR", loc=(49, 3), opt_in=False)   # not active: not counted
    status, hdrs, body = call(env, "GET", "/v1/locations")
    assert status == 200
    assert hdrs["Content-Type"].startswith("application/json")
    assert hdrs["Access-Control-Allow-Origin"] == "*"
    assert body == {
        "locations": [
            {"lat": 53, "lon": 13, "count": 2},
            {"lat": 41, "lon": -75, "count": 2},
            {"lat": 49, "lon": 11, "count": 1},
            {"lat": 37, "lon": -123, "count": 1},
        ],
        "located": 6, "unlocated": 2, "grid_deg": 2, "updated_at": NOW,
    }


def test_locations_empty_and_methods(env):
    status, _, body = call(env, "GET", "/v1/locations")
    assert status == 200
    assert body == {"locations": [], "located": 0, "unlocated": 0, "grid_deg": 2, "updated_at": NOW}
    status, hdrs, _ = call(env, "POST", "/v1/locations")
    assert status == 405 and hdrs.get("Allow") == "GET"


def test_network_shape_unchanged(env):
    add(env, 1, country="DE", loc=(53, 13))
    status, _, body = call(env, "GET", "/v1/network")
    assert status == 200
    assert set(body) == {"nodes_total", "nodes_reachable", "countries", "updated_at"}


def test_docs():
    proto = open(os.path.join(ROOT, "docs", "PROTOCOL.md"), encoding="utf-8").read()
    assert "/v1/locations" in proto and "grid_deg" in proto
    install = open(os.path.join(ROOT, "docs", "INSTALL.md"), encoding="utf-8").read()
    assert "geo_city_csv" in install and "dbip-city-lite" in install and "CC BY 4.0" in install
    readme = open(os.path.join(ROOT, "README.md"), encoding="utf-8").read()
    assert "/v1/locations" in readme
    decisions = open(os.path.join(ROOT, "DECISIONS.md"), encoding="utf-8").read()
    assert "2°" in decisions or "2 degree" in decisions or "GRID_DEG" in decisions
