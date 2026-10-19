"""CSR node probing: ping protocol v1 challenges, outbound check-ins and slot bookkeeping."""
import ipaddress
import json
import math
import random
import socket
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from . import geo as geo_mod
from . import ping, protocol
from .hashing import from_hex
from .prober import _default_post, _is_timeout, slot_of

_EVAL_KEYS = ("peer_id", "service_pubkey", "tip_number", "lag", "in_sync", "csr_version",
              "node_version", "r2_state", "ping_mode")
_STATUS_REASONS = {400: "rejected_400", 403: "bad_monitor_key", 409: "replay",
                   429: "rate_limited", 503: "node_unavailable"}

__all__ = ["slot_of", "evaluate_answer", "CsrProber"]


def _fail(reason) -> dict:
    out = {"result": "fail", "failure_reason": reason}
    out.update({k: None for k in _EVAL_KEYS})
    return out


def evaluate_answer(challenge, body, *, chain, network, elapsed_s, deadline_s, sync_threshold,
                    expected_peer_id=None) -> dict:
    try:
        a, sig = ping.parse_answer(body)
    except ValueError:
        return _fail("bad_format")
    if elapsed_s > deadline_s:
        return _fail("late")
    if a["network"] != network:
        return _fail("wrong_network")
    if a["nonce"] != challenge["nonce"]:
        return _fail("bad_nonce")
    if not ping.verify(a["service_pubkey"], ping.answer_message(a), sig):
        return _fail("bad_signature")
    if not ping.verify_binding(a["peer_id"], a["service_pubkey"], a["network"], a["binding_sig"]):
        return _fail("bad_binding")
    if expected_peer_id is not None and a["peer_id"] != expected_peer_id:
        return _fail("peer_id_mismatch")
    expected = chain.block_hash(challenge["height"])
    if expected is None or a["block_hash_at_height"].lower() != str(expected).lower():
        return _fail("wrong_block_hash")
    if a["tip_number"] < challenge["height"]:
        return _fail("tip_below_height")
    lag = max(0, chain.tip()[0] - a["tip_number"])
    return {"result": "ok", "failure_reason": None, "peer_id": a["peer_id"],
            "service_pubkey": a["service_pubkey"], "tip_number": a["tip_number"], "lag": lag,
            "in_sync": lag <= sync_threshold and a["r2_state"] == "Synced",
            "csr_version": a["csr_version"], "node_version": a["node_version"],
            "r2_state": a["r2_state"], "ping_mode": a["ping_mode"]}


class CsrProber:
    def __init__(self, store, chain, config, monitor_secret, *, geo=None, salt=b"",
                 clock=time.time, rng=None, http_post=None):
        self.store = store
        self.chain = chain
        self.config = config
        self.secret = monitor_secret
        self.geo = geo
        self.salt = salt
        self.clock = clock
        self.rng = rng or random.SystemRandom()
        self.http_post = http_post or _default_post
        self.started_at = clock()
        self.paused = False
        self._lock = threading.RLock()
        self._planned = {}
        self._open = {}          # nonce -> entry dict of an outbound challenge
        self._next_slot = {}     # runner_id -> first outbound slot not yet closed
        self._paused_slots = set()
        self._peers = []

    # ---- helpers ----
    def set_peers(self, peers):
        with self._lock:
            self._peers = list(peers)

    def p2p_verified(self, peer_id) -> bool:
        with self._lock:
            return any(p["node_id"] == peer_id for p in self._peers)

    def planned_time(self, runner_id, slot) -> float:
        with self._lock:
            key = (runner_id, slot)
            if key not in self._planned:
                i, j = self.config.probe_interval_s, self.config.probe_jitter_s
                t = slot * i + i / 2 + self.rng.uniform(-j, j)
                self._planned[key] = min(max(t, slot * i), (slot + 1) * i - 1e-3)
            return self._planned[key]

    def _new_challenge(self, now):
        tip = self.chain.tip()[0]
        with self._lock:
            back = self.rng.randrange(3, 20)
            nonce = bytes(self.rng.getrandbits(8) for _ in range(32))
        return ping.make_challenge(self.secret, height=max(0, tip - back),
                                   issued_at=int(now), nonce=nonce)

    @staticmethod
    def _resolve_ip(endpoint):
        try:
            host = urllib.parse.urlsplit(endpoint or "").hostname
        except ValueError:
            return None
        if not host:
            return None
        try:
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        try:
            return socket.getaddrinfo(host, None)[0][4][0]
        except OSError:
            return None

    def _record(self, runner_id, now, mode, result, reason, *, slot=None, ip=None,
                latency_ms=None, ev=None, p2p_verified=None):
        ev = ev or {}
        rec = {"runner_id": runner_id, "ts": int(now),
               "slot": slot_of(now, self.config.probe_interval_s) if slot is None else slot,
               "mode": mode, "result": result, "failure_reason": reason,
               "latency_ms": latency_ms, "tip_number": ev.get("tip_number"),
               "lag": ev.get("lag"), "in_sync": ev.get("in_sync"),
               "csr_version": ev.get("csr_version"), "ckb_version": ev.get("node_version"),
               "ip_hash": None, "country": None, "asn": None,
               "p2p_verified": p2p_verified if result == "ok" else None}
        loc = None
        if ip:
            rec["ip_hash"] = geo_mod.ip_hash(ip, self.salt)
            if self.geo is not None:
                g = self.geo.lookup(ip)
                rec["country"], rec["asn"] = g["country"], g["asn"]
                locate = getattr(self.geo, "locate", None)
                if locate is not None:
                    loc = locate(ip)
        lat, lon = loc if loc else (None, None)
        self.store.record_probe(**rec, loc_lat=lat, loc_lon=lon)
        return rec

    def _upsert_runner(self, ev, mode, endpoint, now, keep_mode=False):
        pub = ev["service_pubkey"]
        rid = protocol.runner_id(from_hex(pub))
        old = self.store.get_runner(rid)
        if old is None:
            self.store.upsert_runner(rid, service_pubkey=pub, peer_id=ev["peer_id"],
                                     p2p_pubkey="", reg_outpoint="", mode=mode,
                                     endpoint=endpoint, p2p_port=0, ranking_opt_in=True, now=now)
            return rid
        if keep_mode and old["status"] == "active":
            mode, endpoint = old["mode"], old["endpoint"]
        self.store.upsert_runner(rid, service_pubkey=pub, peer_id=ev["peer_id"],
                                 p2p_pubkey=old["p2p_pubkey"], reg_outpoint=old["reg_outpoint"],
                                 mode=mode, endpoint=endpoint, p2p_port=old["p2p_port"],
                                 ranking_opt_in=old["ranking_opt_in"], now=now)
        return rid

    # ---- inbound ----
    def probe_endpoint(self, endpoint, now, expected_peer_id=None) -> dict:
        challenge = self._new_challenge(now)
        url = endpoint.rstrip("/") + "/v1/challenge"
        body = json.dumps(challenge, separators=(",", ":")).encode()
        timeout = self.config.probe_timeout_s
        t0 = time.monotonic()
        try:
            status, raw = self.http_post(url, body, timeout)
        except Exception as e:  # noqa: BLE001 - any transport error is a failed probe
            out = _fail("timeout" if _is_timeout(e) else "unreachable")
            out["latency_ms"] = None
            return out
        elapsed = time.monotonic() - t0
        latency = int(elapsed * 1000)
        if status != 200:
            out = _fail(_STATUS_REASONS.get(status, "bad_status"))
        else:
            try:
                answer = json.loads(raw)
            except (ValueError, TypeError):
                answer = None
            if answer is None and raw not in (b"null", "null"):
                out = _fail("bad_format")
            else:
                out = evaluate_answer(
                    challenge, answer, chain=self.chain, network=self.config.network,
                    elapsed_s=elapsed, deadline_s=timeout,
                    sync_threshold=self.config.sync_threshold, expected_peer_id=expected_peer_id)
        out["latency_ms"] = latency
        return out

    def discover(self, candidates, now) -> list:
        if self.paused or not candidates:
            return []

        def one(c):
            ev = self.probe_endpoint(c["endpoint"], now)
            res = {"node_id": c["node_id"], "endpoint": c["endpoint"], "result": ev["result"],
                   "failure_reason": ev["failure_reason"]}
            ok = ev["result"] == "ok"
            if ok:
                rid = self._upsert_runner(ev, "inbound", c["endpoint"], now)
                res["runner_id"] = rid
                self._record(rid, now, "inbound", "ok", None, ip=c.get("ip"),
                             latency_ms=ev["latency_ms"], ev=ev,
                             p2p_verified=ev["peer_id"] == c["node_id"])
            self.store.discovery_mark(c["ip"], c["node_id"], ts=now, ok=ok)
            return res

        with ThreadPoolExecutor(max_workers=max(1, self.config.probe_workers)) as pool:
            return list(pool.map(one, candidates))

    def probe_inbound(self, runner, now=None):
        now = self.clock() if now is None else now
        rid = runner["runner_id"]
        ip = self._resolve_ip(runner.get("endpoint"))
        if self.paused:
            return self._record(rid, now, "inbound", "excluded", "monitor_paused", ip=ip)
        ev = self.probe_endpoint(runner["endpoint"], now, expected_peer_id=runner["peer_id"])
        if ev["result"] == "ok" and ev["service_pubkey"] != runner["service_pubkey"]:
            ev = dict(_fail("pubkey_changed"), latency_ms=ev["latency_ms"])
        if ev["result"] == "ok":
            self._upsert_runner(ev, "inbound", runner["endpoint"], now, keep_mode=True)
        return self._record(rid, now, "inbound", ev["result"], ev["failure_reason"], ip=ip,
                            latency_ms=ev["latency_ms"], ev=ev,
                            p2p_verified=self.p2p_verified(runner["peer_id"]))

    # ---- scheduling ----
    def _expire_open(self, now):
        deadline = self.config.answer_deadline_s
        with self._lock:
            old = [(n, e) for n, e in self._open.items() if now - e["opened_at"] > deadline]
            for n, _ in old:
                del self._open[n]
        out = []
        for _, e in old:
            if self.store.get_runner(e["runner_id"]) is not None:
                out.append(self._record(e["runner_id"], e["opened_at"], "outbound", "fail",
                                        "no_answer", slot=e["slot"], ip=e["ip"]))
        return out

    def run_due(self, now=None):
        now = self.clock() if now is None else now
        interval = self.config.probe_interval_s
        cur = slot_of(now, interval)
        records = self._expire_open(now)
        if self.paused:
            with self._lock:
                self._paused_slots.add(cur)
        runners = self.store.list_runners(("active",))
        due = [r for r in runners if r["mode"] == "inbound"
               and not self.store.has_probe(r["runner_id"], cur)
               and now >= self.planned_time(r["runner_id"], cur)]
        if due:
            with ThreadPoolExecutor(max_workers=max(1, self.config.probe_workers)) as pool:
                futures = [pool.submit(self.probe_inbound, r, now) for r in due]
                for f in futures:
                    try:
                        records.append(f.result())
                    except Exception:  # noqa: BLE001 - one bad probe must not stop the rest
                        pass
        closed = int(math.floor((now - interval / 2) / interval))   # slots < closed are closed
        for r in runners:
            if r["mode"] != "outbound":
                continue
            rid = r["runner_id"]
            with self._lock:
                start = self._next_slot.get(rid)
                if start is None:
                    start = max(math.ceil(self.started_at / interval),
                                math.ceil(r["first_seen"] / interval))
                self._next_slot[rid] = max(start, closed)
                paused = set(self._paused_slots)
            for k in range(start, closed):
                if self.store.has_probe(rid, k):
                    continue
                at = k * interval
                if k in paused:
                    records.append(self._record(rid, at, "outbound", "excluded", "monitor_paused"))
                else:
                    records.append(self._record(rid, at, "outbound", "fail", "no_checkin"))
        return records

    # ---- outbound ----
    def _eligible(self, runner, k):
        i = self.config.probe_interval_s
        return k * i >= self.started_at and k * i >= runner["first_seen"]

    def handle_checkin(self, body, ip, now=None):
        now = self.clock() if now is None else now
        try:
            c = ping.parse_checkin(body)
        except ValueError:
            return 400, {"error": "bad_request"}
        if c["network"] != self.config.network:
            return 400, {"error": "wrong_network"}
        if not ping.verify_binding(c["peer_id"], c["service_pubkey"], c["network"],
                                   c["binding_sig"]):
            return 401, {"error": "bad_signature"}
        if self.paused:
            return 503, {"error": "monitor_paused"}
        interval = self.config.probe_interval_s
        rid = protocol.runner_id(from_hex(c["service_pubkey"]))
        runner = self.store.get_runner(rid)
        s = slot_of(now, interval)
        slot = None
        if runner is not None and runner["status"] == "active":
            if (now - s * interval < interval / 2 and self._eligible(runner, s - 1)
                    and not self.store.has_probe(rid, s - 1)):
                slot = s - 1
            elif not self.store.has_probe(rid, s):
                slot = s
        else:
            slot = s
        if slot is None:
            return 429, {"error": "slot_done"}
        deadline = self.config.answer_deadline_s
        challenge = self._new_challenge(now)
        with self._lock:
            if any(e["runner_id"] == rid and now - e["opened_at"] < deadline
                   for e in self._open.values()):
                return 429, {"error": "challenge_open"}
            self._open[challenge["nonce"]] = {
                "runner_id": rid, "peer_id": c["peer_id"], "service_pubkey": c["service_pubkey"],
                "ip": ip, "opened_at": now, "slot": slot, "challenge": challenge}
        return 200, {"challenge": challenge}

    def handle_answer(self, body, ip, now=None):
        now = self.clock() if now is None else now
        nonce = body.get("answer", {}).get("nonce") if (
            isinstance(body, dict) and isinstance(body.get("answer"), dict)) else None
        if not isinstance(nonce, str):
            return 400, {"error": "bad_request"}
        with self._lock:
            e = self._open.pop(nonce, None)
        if e is None:
            return 409, {"error": "unknown_nonce"}
        elapsed = now - e["opened_at"]
        ev = evaluate_answer(
            e["challenge"], body, chain=self.chain, network=self.config.network,
            elapsed_s=elapsed, deadline_s=self.config.answer_deadline_s,
            sync_threshold=self.config.sync_threshold, expected_peer_id=e["peer_id"])
        if ev["result"] == "ok" and ev["service_pubkey"] != e["service_pubkey"]:
            ev = _fail("pubkey_changed")
        rid = e["runner_id"]
        latency = int(elapsed * 1000)
        if ev["result"] == "ok":
            rid = self._upsert_runner(ev, "outbound", "", now, keep_mode=True)
            self._record(rid, now, "outbound", "ok", None, slot=e["slot"], ip=e["ip"],
                         latency_ms=latency, ev=ev, p2p_verified=self.p2p_verified(ev["peer_id"]))
            return 200, {"result": "ok"}
        if self.store.get_runner(rid) is not None:
            self._record(rid, now, "outbound", "fail", ev["failure_reason"], slot=e["slot"],
                         ip=e["ip"], latency_ms=latency)
        return 422, {"result": "fail", "failure_reason": ev["failure_reason"]}
