"""node-identity-monitor: identity gate in the ranking, proof for an unknown runner, POST rate limit."""
import json
import random
import sqlite3

from csrmon import api as api_mod, config as config_mod, crypto, csrprobe, p2p, ping, protocol, scoring
from csrmon import store as store_mod
from csrmon.hashing import to_hex
from fakes_v2 import FakeChainV2

S = 1_792_281_600
TODAY = store_mod.day_of(S)


def env(tmp_path, **extra):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    lines += [f"{k} = {json.dumps(v)}" for k, v in extra.items()]
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    c = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(c.db_path)
    fc = FakeChainV2(tip=1000)
    mon = (0x51).to_bytes(32, "big")
    pr = csrprobe.CsrProber(st, fc, c, mon, clock=lambda: S, rng=random.Random(1))
    return c, st, api_mod.Api(st, c, mon, prober=pr, chain=fc, clock=lambda: S)


def proof(service_sk, p2p_sk, ts=S, network="testnet"):
    spk = to_hex(crypto.pubkey_from_secret(service_sk))
    ppk = crypto.pubkey_from_secret(p2p_sk)
    peer = p2p.peer_id_from_pubkey(ppk)
    m = p2p.identity_message(peer, spk, network, ts)
    return {"peer_id": peer, "service_pubkey": spk, "network": network, "ts": ts, "p2p_pubkey": to_hex(ppk),
            "p2p_sig": ping.sign(p2p_sk, m), "service_sig": ping.sign(service_sk, m)}


def post(a, body):
    status, _, data = a.handle("POST", "/v1/identity", {}, json.dumps(body).encode(), "203.0.113.4")
    return status, json.loads(data)


def add(st, c, n, proven_at=None):
    sk = n.to_bytes(32, "big")
    rid = protocol.runner_id(crypto.pubkey_from_secret(sk))
    st.upsert_runner(rid, service_pubkey=to_hex(crypto.pubkey_from_secret(sk)), peer_id=f"Qm{n}",
                     p2p_pubkey="", reg_outpoint="", mode="outbound", endpoint="", p2p_port=0,
                     ranking_opt_in=True, now=S - 40 * 86400)
    if proven_at is not None:
        st.set_identity(rid, p2p_pubkey="0x02", proven_at=proven_at)
    con = sqlite3.connect(c.db_path)
    con.execute("insert into daily_stats(runner_id, day, probes_total, probes_ok, in_sync, p2p_total,"
                " p2p_ok) values (?,?,10,10,10,0,0)", (rid, TODAY))
    con.commit()
    con.close()
    return rid


def test_ranking_requires_a_fresh_proof_only_when_configured(tmp_path):
    c, st, _ = env(tmp_path)
    fresh, old, none = add(st, c, 1, S - 86400), add(st, c, 2, S - 8 * 86400), add(st, c, 3)
    loose = {i["runner_id"]: i for i in scoring.rank_runners(st, TODAY, now=S)}
    assert all(loose[r]["rank"] is not None for r in (fresh, old, none))
    strict = {i["runner_id"]: i for i in scoring.rank_runners(st, TODAY, require_identity=True, now=S)}
    assert strict[fresh]["rank"] == 1 and strict[fresh]["unranked_reason"] is None
    assert strict[old]["rank"] is None and strict[old]["unranked_reason"] == "identity_unproven"
    assert strict[none]["rank"] is None and strict[none]["unranked_reason"] == "identity_unproven"


def test_runner_answer_shows_the_reason(tmp_path):
    c, st, a = env(tmp_path, require_identity_proof=True)
    rid = add(st, c, 1)
    status, _, data = a.handle("GET", f"/v1/testnet/runners/{rid}", {}, b"", "10.0.0.1")
    d = json.loads(data)
    assert status == 200 and d["rank"] is None and d["unranked_reason"] == "identity_unproven"
    assert d["identity_proven_at"] is None and d["check_type"] == "challenge_only"
    status, _, data = a.handle("GET", "/v1/monitor", {}, b"", "10.0.0.1")
    assert json.loads(data)["p2p_address"] is None


def test_proof_creates_an_unknown_runner(tmp_path):
    _, st, a = env(tmp_path)
    sk, psk = (5).to_bytes(32, "big"), (6).to_bytes(32, "big")
    body = proof(sk, psk)
    assert post(a, body) == (200, {"ok": True})
    r = st.get_runner(protocol.runner_id(crypto.pubkey_from_secret(sk)))
    assert r["peer_id"] == body["peer_id"] and r["mode"] == "outbound" and r["identity_proven_at"] == S
    assert post(a, proof(sk, psk, network="mainnet")) == (400, {"error": "wrong_network"})
    assert post(a, dict(body, extra=1)) == (400, {"error": "bad_request"})


def test_identity_posts_are_rate_limited(tmp_path):
    _, _, a = env(tmp_path, rate_limit_per_min=2)
    body = proof((5).to_bytes(32, "big"), (6).to_bytes(32, "big"))
    assert [post(a, body)[0] for _ in range(3)] == [200, 200, 429]
