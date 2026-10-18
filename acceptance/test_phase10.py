"""Phase 10 acceptance: weekly epochs, Merkle tree, signed epoch data."""
import json
import sqlite3

import pytest

from csrmon import epochs, crypto, scoring, store as store_mod, config as config_mod, api as api_mod
from csrmon.hashing import ckb_blake2b, from_hex, to_hex
from fakes import FakeChain, GENESIS_MS, BLOCK_MS

MON = (11).to_bytes(32, "big")
SUN = 1792281600          # 2026-10-18 00:00 UTC, a Sunday
MON_DAY = 1792368000      # 2026-10-19 00:00 UTC, a Monday
WEEK = 604800


def test_epoch_calendar():
    assert epochs.EPOCH_SECONDS == WEEK
    assert epochs.first_epoch_start(SUN + 5000) == MON_DAY
    assert epochs.first_epoch_start(MON_DAY) == MON_DAY
    assert epochs.first_epoch_start(MON_DAY + 1) == MON_DAY + WEEK
    assert epochs.epoch_bounds(SUN + 5000, 1) == (MON_DAY, MON_DAY + WEEK)
    assert epochs.epoch_bounds(SUN + 5000, 3) == (MON_DAY + 2 * WEEK, MON_DAY + 3 * WEEK)
    assert epochs.epoch_at(SUN + 5000, SUN + 6000) == 0
    assert epochs.epoch_at(SUN + 5000, MON_DAY) == 1
    assert epochs.epoch_at(SUN + 5000, MON_DAY + WEEK - 1) == 1
    assert epochs.epoch_at(SUN + 5000, MON_DAY + WEEK) == 2
    assert epochs.pending_epochs(SUN + 5000, MON_DAY + 3 * WEEK + 10, built=[1]) == [2, 3]
    assert epochs.pending_epochs(SUN + 5000, MON_DAY + WEEK - 1, built=[]) == []


def test_encode_leaf():
    rid = "0x" + "ab" * 32
    leaf = epochs.encode_leaf(rid, score=87.456, a30=0.99876, a365=0.5, f30=1.0,
                              country="de", asn=3320, flags=epochs.FLAG_PROVISIONAL)
    assert len(leaf) == 47
    assert leaf[:32] == bytes.fromhex("ab" * 32)
    assert int.from_bytes(leaf[32:34], "little") == 8746
    assert int.from_bytes(leaf[34:36], "little") == 9988
    assert int.from_bytes(leaf[36:38], "little") == 5000
    assert int.from_bytes(leaf[38:40], "little") == 10000
    assert leaf[40:42] == b"DE"
    assert int.from_bytes(leaf[42:46], "little") == 3320
    assert leaf[46] == 1
    assert epochs.FLAG_IDENTITY_MISMATCH == 2 and epochs.FLAG_BAD_BINDING == 4
    unknown = epochs.encode_leaf(rid, score=0, a30=0, a365=0, f30=0, country=None, asn=None, flags=0)
    assert unknown[40:42] == b"??" and unknown[42:46] == b"\x00" * 4
    assert epochs.decode_leaf(leaf) == {"runner_id": rid, "score": 87.46, "a30": 0.9988,
                                        "a365": 0.5, "f30": 1.0, "country": "DE", "asn": 3320,
                                        "flags": 1}


def ref_root(leaves):
    level = [ckb_blake2b(b"\x00" + l) for l in leaves]
    if not level:
        return b"\x00" * 32
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(ckb_blake2b(b"\x01" + level[i] + level[i + 1]))
            else:
                nxt.append(level[i])
        level = nxt
    return level[0]


@pytest.mark.parametrize("n", [0, 1, 2, 3, 5, 8, 13])
def test_merkle(n):
    leaves = [bytes([i]) * 47 for i in range(n)]
    root = epochs.merkle_root(leaves)
    assert root == ref_root(leaves)
    for i in range(n):
        proof = epochs.merkle_proof(leaves, i)
        assert all(p["side"] in ("left", "right") and len(from_hex(p["hash"])) == 32 for p in proof)
        assert epochs.verify_proof(leaves[i], proof, root)
        assert not epochs.verify_proof(b"\xff" * 47, proof, root)
        if proof:
            bad = [dict(p) for p in proof]
            bad[0]["side"] = "left" if bad[0]["side"] == "right" else "right"
            assert not epochs.verify_proof(leaves[i], bad, root) or n == 1


def test_leaf_hash_and_single_leaf():
    leaf = b"\x01" * 47
    assert epochs.leaf_hash(leaf) == ckb_blake2b(b"\x00" + leaf)
    assert epochs.node_hash(b"a" * 32, b"b" * 32) == ckb_blake2b(b"\x01" + b"a" * 32 + b"b" * 32)
    assert epochs.merkle_root([leaf]) == epochs.leaf_hash(leaf)
    assert epochs.merkle_proof([leaf], 0) == []


def test_epoch_data_encoding():
    fields = dict(epoch=7, start_block=100, end_block=200, runner_count=61, country_count=12,
                  asn_count=40, score_formula=1, merkle_root=b"\x11" * 32,
                  prev_epoch_hash=b"\x22" * 32)
    unsigned = epochs.epoch_unsigned_bytes(**fields)
    assert len(unsigned) == 94
    assert unsigned[0] == 1
    assert unsigned[1:5] == (7).to_bytes(4, "little")
    assert unsigned[5:13] == (100).to_bytes(8, "little")
    assert unsigned[13:21] == (200).to_bytes(8, "little")
    assert unsigned[21:25] == (61).to_bytes(4, "little")
    assert unsigned[25:27] == (12).to_bytes(2, "little")
    assert unsigned[27:29] == (40).to_bytes(2, "little")
    assert unsigned[29] == 1
    assert unsigned[30:62] == b"\x11" * 32 and unsigned[62:94] == b"\x22" * 32
    data = epochs.sign_epoch_data(MON, unsigned)
    assert len(data) == 159 and data[:94] == unsigned
    pk = crypto.pubkey_from_secret(MON)
    assert crypto.verify(pk, ckb_blake2b(b"CSR/v1/epoch" + unsigned), data[94:])
    assert epochs.verify_epoch_data(data, pk)
    assert not epochs.verify_epoch_data(data[:5] + b"\x09" + data[6:], pk)
    d = epochs.decode_epoch_data(data)
    assert d == {"version": 1, "epoch": 7, "start_block": 100, "end_block": 200, "runner_count": 61,
                 "country_count": 12, "asn_count": 40, "score_formula": 1,
                 "merkle_root": "0x" + "11" * 32, "prev_epoch_hash": "0x" + "22" * 32,
                 "monitor_sig": to_hex(data[94:])}


# ---------- building epochs ----------

def rid(n):
    return "0x" + f"{(n * 7919) % 1000:064x}"   # ids not in insertion order


@pytest.fixture
def env(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    cfg = config_mod.load_config(str(tmp_path / "c.toml"))
    st = store_mod.Store(cfg.db_path)
    start = SUN - 40 * 86400 + 5000          # monitor started on a Tuesday, 40+ days earlier
    st.set_meta("monitor_start", str(start))
    specs = [(1, "DE", 3320, 60, []), (2, "US", 7922, 60, []), (3, "DE", 3320, 60, []),
             (4, "JP", 2516, 2, []), (5, "FR", 12322, 60, ["identity_mismatch"])]
    for n, cc, asn, age, flags in specs:
        st.upsert_runner(rid(n), service_pubkey="0x02", peer_id=f"Qm{n}", p2p_pubkey="0x03",
                         reg_outpoint="0x0:0", mode="pull", endpoint="https://x", p2p_port=0,
                         ranking_opt_in=True, now=SUN - age * 86400)
        for f in flags:
            st.set_flag(rid(n), f, True)
    con = sqlite3.connect(cfg.db_path)
    for n, cc, asn, age, flags in specs:
        con.execute("update runners set country=?, region=?, asn=? where runner_id=?",
                    (cc, "EU", asn, rid(n)))
        for d in range(70):
            con.execute("insert into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                        " p2p_total, p2p_ok, median_lag, median_peers, score)"
                        " values (?,?,?,?,?,?,?,?,?,null)",
                        (rid(n), store_mod.add_days("2026-10-18", -d), 144, 130 + n, 120, 1, 1, 1, 8))
    con.commit()
    con.close()
    fc = FakeChain(tip=12_000_000)
    return {"cfg": cfg, "st": st, "chain": fc, "start": start}


def test_build_epoch(env):
    st, fc, start = env["st"], env["chain"], env["start"]
    s, e = epochs.epoch_bounds(start, 5)
    assert e <= SUN + 86400
    assert epochs.build_pending(st, fc, MON, env["cfg"], now=e + 60) == [1, 2, 3, 4, 5]
    summary = epochs.build_epoch(st, fc, MON, env["cfg"], 5, now=e + 60)
    assert summary["epoch"] == 5 and summary["start"] == s and summary["end"] == e
    assert summary["start_block"] == (s * 1000 - GENESIS_MS) // BLOCK_MS
    assert summary["end_block"] == (e * 1000 - 1 - GENESIS_MS) // BLOCK_MS
    assert summary["score_formula"] == "score_v1"
    assert summary["monitor_pubkey"] == to_hex(crypto.pubkey_from_secret(MON))
    day = store_mod.day_of(e - 1)
    ranking = scoring.rank_runners(st, day)
    ranked = [r for r in ranking if r["rank"] is not None]
    assert summary["runner_count"] == len(ranked) == 3
    assert summary["country_count"] == 2 and summary["asn_count"] == 2
    leaves = summary["leaves"]
    assert [l["runner_id"] for l in leaves] == sorted(r["runner_id"] for r in ranking)
    assert len(leaves) == 5
    root = from_hex(summary["merkle_root"])
    raw = [from_hex(l["leaf_hex"]) for l in leaves]
    assert root == ref_root(raw)
    by = {r["runner_id"]: r for r in ranking}
    for l, leaf in zip(leaves, raw):
        assert epochs.verify_proof(leaf, l["proof"], root)
        dec = epochs.decode_leaf(leaf)
        assert {k: l[k] for k in dec} == dec
        assert dec["score"] == pytest.approx(by[l["runner_id"]]["score"], abs=0.006)
    flags = {l["runner_id"]: l["flags"] for l in leaves}
    assert flags[rid(4)] == epochs.FLAG_PROVISIONAL
    assert flags[rid(5)] == epochs.FLAG_IDENTITY_MISMATCH
    assert flags[rid(1)] == 0
    data = from_hex(summary["data_hex"])
    assert epochs.verify_epoch_data(data, crypto.pubkey_from_secret(MON))
    d = epochs.decode_epoch_data(data)
    assert d["epoch"] == 5 and d["merkle_root"] == summary["merkle_root"]
    assert d["start_block"] == summary["start_block"] and d["runner_count"] == 3
    assert d["prev_epoch_hash"] == summary["prev_epoch_hash"]
    stored = st.get_epoch(5)
    assert stored["merkle_root"] == summary["merkle_root"] and stored["data_hex"] == summary["data_hex"]
    assert stored["summary"] == json.loads(json.dumps(summary))


def test_epoch_chain_and_rules(env):
    st, fc, start, cfg = env["st"], env["chain"], env["start"], env["cfg"]
    s1, e1 = epochs.epoch_bounds(start, 1)
    with pytest.raises(ValueError):
        epochs.build_epoch(st, fc, MON, cfg, 1, now=e1 - 1)     # not finished yet
    with pytest.raises(ValueError):
        epochs.build_epoch(st, fc, MON, cfg, 2, now=e1 + WEEK)  # epoch 1 missing
    one = epochs.build_epoch(st, fc, MON, cfg, 1, now=e1 + 1)
    assert one["prev_epoch_hash"] == "0x" + "00" * 32
    assert epochs.build_epoch(st, fc, MON, cfg, 1, now=e1 + 999) == one   # idempotent
    two = epochs.build_epoch(st, fc, MON, cfg, 2, now=e1 + WEEK)
    assert two["prev_epoch_hash"] == to_hex(ckb_blake2b(from_hex(one["data_hex"])))
    built = epochs.build_pending(st, fc, MON, cfg, now=e1 + 3 * WEEK + 5)
    assert built == [3, 4]
    assert [e["epoch"] for e in st.list_epochs()] == [1, 2, 3, 4]


def test_epoch_api(env):
    st, fc, start, cfg = env["st"], env["chain"], env["start"], env["cfg"]
    _, e1 = epochs.epoch_bounds(start, 1)
    one = epochs.build_epoch(st, fc, MON, cfg, 1, now=e1 + 1)
    api = api_mod.Api(st, cfg, MON, chain=fc, clock=lambda: e1 + 100)
    status, _, body = api.handle("GET", "/v1/testnet/epochs/1", {}, b"", "1.1.1.1")
    body = json.loads(body)
    assert status == 200 and body["stat_cell_tx"] is None
    for k in ("merkle_root", "data_hex", "leaves", "prev_epoch_hash", "start_block", "end_block"):
        assert body[k] == one[k], k
    status, _, body = api.handle("GET", "/v1/testnet/epochs", {}, b"", "1.1.1.2")
    assert json.loads(body)["items"][0]["merkle_root"] == one["merkle_root"]
