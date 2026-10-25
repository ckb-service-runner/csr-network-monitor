"""Response evaluation, pull probes, push check-ins and slot bookkeeping."""
import ipaddress
import json
import math
import os
import random
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from . import geo as geo_mod
from . import protocol
from .hashing import from_hex

_STR_FIELDS = ("nonce", "peer_id", "tip_hash", "block_hash", "csr_version", "ckb_version", "sig")
_EVAL_KEYS = ("tip_number", "lag", "in_sync", "peers_out", "csr_version", "ckb_version")
CHECKIN_SKEW_S = 120


def slot_of(ts, interval) -> int:
    return int(ts // interval)


def _is_int(x):
    return isinstance(x, int) and not isinstance(x, bool)


def _format_ok(r) -> bool:
    if not isinstance(r, dict) or not _is_int(r.get("v")) or r["v"] != 1:
        return False
    if any(not isinstance(r.get(k), str) for k in _STR_FIELDS):
        return False
    for k in ("tip_number", "peers_out"):
        if not _is_int(r.get(k)) or r[k] < 0:
            return False
    return isinstance(r.get("ibd"), bool)


def _fail(reason) -> dict:
    out = {"result": "fail", "failure_reason": reason}
    out.update({k: None for k in _EVAL_KEYS})
    return out


def evaluate_response(challenge, response, *, service_pubkey, peer_id, chain, elapsed_s,
                      timeout_s, sync_threshold) -> dict:
    if not _format_ok(response):
        return _fail("bad_format")
    if elapsed_s > timeout_s:
        return _fail("late")
    if response["nonce"] != challenge["nonce"]:
        return _fail("bad_nonce")
    if not protocol.verify_response_sig(challenge, response, service_pubkey):
        return _fail("bad_signature")
    if response["peer_id"] != peer_id:
        return _fail("peer_id_mismatch")
    expected = chain.block_hash(challenge["block_height"])
    if expected is None or response["block_hash"].lower() != str(expected).lower():
        return _fail("wrong_block_hash")
    mtip = chain.tip()[0]
    tip = response["tip_number"]
    if tip > mtip + sync_threshold:
        return _fail("unknown_tip")
    if tip <= mtip:
        h = chain.block_hash(tip)
        if h is None or response["tip_hash"].lower() != str(h).lower():
            return _fail("unknown_tip")
    lag = max(0, mtip - tip)
    return {"result": "ok", "failure_reason": None, "tip_number": tip, "lag": lag,
            "in_sync": lag <= sync_threshold and not response["ibd"],
            "peers_out": response["peers_out"], "csr_version": response["csr_version"],
            "ckb_version": response["ckb_version"]}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Probes never follow redirects: a 3xx answer is just a bad status."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _default_post(url, body, timeout):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, b""


def _is_timeout(e) -> bool:
    if isinstance(e, (socket.timeout, TimeoutError)):
        return True
    return isinstance(e, urllib.error.URLError) and isinstance(
        e.reason, (socket.timeout, TimeoutError))


class Prober:
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
        self._open = {}          # runner_id -> (challenge, opened_at, ip)
        self._next_slot = {}     # runner_id -> first push slot not yet closed
        self._paused_slots = set()

    # ---- helpers ----
    def planned_time(self, runner_id, slot) -> float:
        with self._lock:
            key = (runner_id, slot)
            if key not in self._planned:
                i, j = self.config.probe_interval_s, self.config.probe_jitter_s
                t = slot * i + i / 2 + self.rng.uniform(-j, j)
                self._planned[key] = min(max(t, slot * i), (slot + 1) * i - 1e-3)
            return self._planned[key]

    def _new_challenge(self, now):
        mtip = self.chain.tip()[0]
        with self._lock:
            back = self.rng.randrange(0, 100)
            nonce = bytes(self.rng.getrandbits(8) for _ in range(32))
        return protocol.make_challenge(
            self.secret, network=self.config.network, monitor_tip=mtip,
            block_height=max(0, mtip - back), issued_at=int(now), nonce=nonce)

    def _resolve_ip(self, host):
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

    def _record(self, runner_id, now, mode, result, reason, ip=None, latency_ms=None, ev=None):
        ev = ev or {}
        rec = {"runner_id": runner_id, "ts": int(now),
               "slot": slot_of(now, self.config.probe_interval_s), "mode": mode,
               "result": result, "failure_reason": reason, "latency_ms": latency_ms,
               "ip_hash": None, "country": None, "asn": None}
        for k in _EVAL_KEYS:
            rec[k] = ev.get(k)
        if ip:
            rec["ip_hash"] = geo_mod.ip_hash(ip, self.salt)
            if self.geo is not None:
                g = self.geo.lookup(ip)
                rec["country"], rec["asn"] = g["country"], g["asn"]
        self.store.record_probe(**rec)
        return rec

    def _evaluate(self, runner, challenge, response, elapsed):
        return evaluate_response(
            challenge, response, service_pubkey=from_hex(runner["service_pubkey"]),
            peer_id=runner["peer_id"], chain=self.chain, elapsed_s=elapsed,
            timeout_s=self.config.probe_timeout_s, sync_threshold=self.config.sync_threshold)

    # ---- pull ----
    def probe_pull(self, runner, now=None):
        now = self.clock() if now is None else now
        rid = runner["runner_id"]
        host = urllib.parse.urlsplit(runner.get("endpoint") or "").hostname
        ip = self._resolve_ip(host)
        if self.paused:
            return self._record(rid, now, "pull", "excluded", "monitor_paused", ip)
        challenge = self._new_challenge(now)
        url = runner["endpoint"].rstrip("/") + "/csr/v1/probe"
        t0 = time.monotonic()
        try:
            status, body = self.http_post(url, protocol.canonical_json(challenge),
                                          self.config.probe_timeout_s)
        except Exception as e:  # noqa: BLE001 - any transport error is a failed probe
            reason = "timeout" if _is_timeout(e) else "unreachable"
            return self._record(rid, now, "pull", "fail", reason, ip)
        elapsed = time.monotonic() - t0
        latency = int(elapsed * 1000)
        if status != 200:
            return self._record(rid, now, "pull", "fail", "bad_status", ip, latency)
        try:
            response = json.loads(body)
        except (ValueError, TypeError):
            return self._record(rid, now, "pull", "fail", "bad_format", ip, latency)
        ev = self._evaluate(runner, challenge, response, elapsed)
        return self._record(rid, now, "pull", ev["result"], ev["failure_reason"], ip, latency, ev)

    def _expire_open(self, now):
        timeout = self.config.probe_timeout_s
        with self._lock:
            old = [(rid, v) for rid, v in self._open.items() if now - v[1] > timeout]
            for rid, _ in old:
                del self._open[rid]
        return [self._record(rid, opened, "push", "fail", "no_response", ip)
                for rid, (_, opened, ip) in old]

    def run_due(self, now=None):
        now = self.clock() if now is None else now
        interval = self.config.probe_interval_s
        cur = slot_of(now, interval)
        records = self._expire_open(now)
        if self.paused:
            with self._lock:
                self._paused_slots.add(cur)
        runners = self.store.list_runners(("active",))
        due = [r for r in runners if r["mode"] == "pull"
               and not self.store.has_probe(r["runner_id"], cur)
               and now >= self.planned_time(r["runner_id"], cur)]
        if due:
            with ThreadPoolExecutor(max_workers=max(1, self.config.probe_workers)) as pool:
                futures = [pool.submit(self.probe_pull, r, now) for r in due]
                for f in futures:
                    try:
                        records.append(f.result())
                    except Exception:  # noqa: BLE001 - one bad probe must not stop the rest
                        pass
        for r in runners:
            if r["mode"] != "push":
                continue
            rid = r["runner_id"]
            with self._lock:
                start = self._next_slot.get(rid)
                if start is None:
                    start = max(math.ceil(self.started_at / interval),
                                math.ceil(r["first_seen"] / interval))
                hi = cur
                if rid in self._open:
                    hi = min(hi, slot_of(self._open[rid][1], interval))
                self._next_slot[rid] = max(start, hi)
                paused = set(self._paused_slots)
            for k in range(start, hi):
                if self.store.has_probe(rid, k):
                    continue
                at = k * interval
                if k in paused:
                    records.append(self._record(rid, at, "push", "excluded", "monitor_paused"))
                else:
                    records.append(self._record(rid, at, "push", "fail", "no_checkin"))
        return records

    # ---- push ----
    def handle_checkin(self, body, ip, now=None):
        now = self.clock() if now is None else now
        if (not isinstance(body, dict) or not isinstance(body.get("runner_id"), str)
                or not _is_int(body.get("ts")) or not isinstance(body.get("sig"), str)):
            return 400, {"error": "bad_request"}
        rid = body["runner_id"].lower()
        runner = self.store.get_runner(rid)
        if runner is None or runner["status"] != "active":
            return 404, {"error": "unknown_runner"}
        if abs(body["ts"] - now) > CHECKIN_SKEW_S:
            return 400, {"error": "stale_timestamp"}
        if not protocol.verify_checkin(dict(body, runner_id=rid),
                                       from_hex(runner["service_pubkey"]), self.config.network):
            return 401, {"error": "bad_signature"}
        if self.paused:
            return 503, {"error": "monitor_paused"}
        self._expire_open(now)
        slot = slot_of(now, self.config.probe_interval_s)
        if self.store.has_probe(rid, slot):
            return 429, {"error": "slot_done"}
        challenge = self._new_challenge(now)
        with self._lock:
            if rid in self._open:
                return 429, {"error": "challenge_open"}
            self._open[rid] = (challenge, now, ip)
        return 200, {"challenge": challenge, "deadline_s": self.config.probe_timeout_s}

    def handle_checkin_response(self, body, ip, now=None):
        now = self.clock() if now is None else now
        if (not isinstance(body, dict) or not isinstance(body.get("runner_id"), str)
                or not isinstance(body.get("response"), dict)):
            return 400, {"error": "bad_request"}
        rid = body["runner_id"].lower()
        with self._lock:
            entry = self._open.pop(rid, None)
        runner = self.store.get_runner(rid)
        if entry is None or runner is None:
            return 409, {"error": "no_open_challenge"}
        challenge, opened, checkin_ip = entry
        elapsed = now - opened
        ev = self._evaluate(runner, challenge, body["response"], elapsed)
        self._record(rid, opened, "push", ev["result"], ev["failure_reason"], checkin_ip,
                     int(elapsed * 1000), ev)
        return 200, {"result": ev["result"], "failure_reason": ev["failure_reason"],
                     "lag": ev["lag"], "in_sync": ev["in_sync"]}
