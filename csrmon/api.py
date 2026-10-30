"""Public REST API and HTTP server."""
import base64
import json
import logging
import math
import os
import statistics
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from . import configcell, geo, scoring
from . import __version__
from .store import add_days, day_of, day_start

log = logging.getLogger("csrmon")
MAX_BODY = 16384
CACHE_TTL_S = 30
P2P_VERIFIED_S = 48 * 3600
_RANK_KEYS = ("runner_id", "rank", "score", "provisional", "status", "flags", "a7", "a30",
              "a365", "country", "region", "asn", "asn_peers", "stake_status")
_WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
_STATIC_TYPES = {".html": "text/html; charset=utf-8", ".mjs": "text/javascript; charset=utf-8",
                 ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
                 ".svg": "image/svg+xml"}
_JSON_HEADERS = {"Content-Type": "application/json; charset=utf-8",
                 "Access-Control-Allow-Origin": "*", "Cache-Control": "no-store",
                 "X-Content-Type-Options": "nosniff"}
_CSP = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'"

_POST_ROUTES = ("/v1/checkin", "/v1/answer", "/v1/attest")


class _Reply(Exception):
    def __init__(self, status, obj, headers=None):
        self.status, self.obj, self.headers = status, obj, headers or {}


def _err(status, code, headers=None):
    return _Reply(status, {"error": code}, headers)


def _whole(x):
    return int(x) if isinstance(x, float) and x == int(x) else x


def _median(vals):
    return _whole(statistics.median(vals)) if vals else None


class Api:
    def __init__(self, store, config, monitor_secret, *, prober=None, chain=None, attester=None,
                 clock=time.time, version=__version__, cross=None):
        from .crypto import pubkey_from_secret
        self.store, self.config, self.prober, self.chain = store, config, prober, chain
        self.attester, self.cross = attester, cross
        self.clock, self.version = clock, version
        self.pubkey = "0x" + pubkey_from_secret(monitor_secret).hex()
        self._lock = threading.Lock()
        self._cache = {}
        self._hits = {}
        self._post_hits = {}

    def invalidate(self):
        with self._lock:
            self._cache.clear()

    # ---- helpers ----
    def _client_ip(self, headers, client_ip):
        if client_ip in self.config.trusted_proxies:
            xff = headers.get("x-forwarded-for")
            if xff:
                last = xff.split(",")[-1].strip()
                if last:
                    return last
        return client_ip

    def _rate_check(self, ip, post=False):
        now = self.clock()
        hits = self._post_hits if post else self._hits
        limit = self.config.rate_limit_post_per_min if post else self.config.rate_limit_per_min
        with self._lock:
            dq = hits.setdefault(ip, deque())
            while dq and dq[0] <= now - 60:
                dq.popleft()
            if len(dq) >= limit:
                retry = max(1, math.ceil(dq[0] + 60 - now))
                raise _err(429, "rate_limited", {"Retry-After": str(retry)})
            dq.append(now)
            if len(hits) > 10000:
                for k in [k for k, v in hits.items() if not v or v[-1] <= now - 60]:
                    del hits[k]

    def _ranking(self, today):
        now = self.clock()
        key = ("ranking", today)
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < CACHE_TTL_S:
                return hit[1]
        ranking = scoring.rank_runners(self.store, today, self.config.provisional_days,
                                        scoring.stake_required(self.config),
                                        require_identity=self.config.require_identity_proof, now=now)
        summary = scoring.network_summary(self.store, today, self.config, ranking)
        with self._lock:
            self._cache[key] = (now, ranking)
            self._cache[("summary", today)] = (now, summary)
        return ranking

    def _summary(self, today):
        self._ranking(today)
        with self._lock:
            return self._cache[("summary", today)][1]

    # ---- entry point ----
    def handle(self, method, target, headers, body, client_ip):
        headers = {str(k).lower(): v for k, v in (headers or {}).items()}
        parts = urlsplit(target)
        path = parts.path
        if method == "GET":
            static = self._static(path)
            if static is not None:
                return static
        if not path.startswith("/v1/"):
            return self._out(404, {"error": "not_found"}, {}, json_body=False)
        try:
            ip = self._client_ip(headers, client_ip)
            if method == "GET" or path.rstrip("/") == "/v1/identity":
                self._rate_check(ip)
            elif method == "POST" and path.rstrip("/") in _POST_ROUTES:
                self._rate_check(ip, post=True)
            obj = self._route(method, path, parse_qs(parts.query), body, ip)
            return self._out(200, obj, {})
        except _Reply as r:
            return self._out(r.status, r.obj, r.headers)
        except Exception:
            log.exception("unhandled error for %s %s", method, path)
            return self._out(500, {"error": "internal"}, {})

    @staticmethod
    def _static(path):
        if path == "/":
            name = "index.html"
        elif path.startswith("/static/"):
            name = path[len("/static/"):]
            ext = os.path.splitext(name)[1]
            if (not name or "/" in name or "\\" in name or name.startswith(".")
                    or ext not in _STATIC_TYPES):
                return None
        else:
            return None
        try:
            with open(os.path.join(_WEB_DIR, name), "rb") as f:
                data = f.read()
        except OSError:
            return None
        ctype = _STATIC_TYPES[os.path.splitext(name)[1]]
        return 200, {"Content-Type": ctype, "Cache-Control": "no-cache",
                     "Content-Security-Policy": _CSP, "X-Content-Type-Options": "nosniff",
                     "X-Frame-Options": "DENY"}, data

    @staticmethod
    def _out(status, obj, extra, json_body=True):
        hdrs = dict(_JSON_HEADERS)
        hdrs.update(extra)
        return status, hdrs, json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()

    def _route(self, method, path, query, body, ip):
        segs = path[len("/v1/"):].strip("/").split("/") if path != "/v1/" else [""]
        today = day_of(self.clock())
        if segs in (["checkin"], ["answer"], ["attest"], ["identity"]):
            self._method(method, "POST")
            return self._post_csr(segs[0], body, ip)
        if segs == ["network"]:
            self._method(method, "GET")
            return self._network()
        if segs == ["locations"]:
            self._method(method, "GET")
            return self._locations()
        if len(segs) == 2 and segs[0] == "nodes":
            self._method(method, "GET")
            return self._node(unquote(segs[1]), today)
        if segs == ["monitor"]:
            self._method(method, "GET")
            return self._monitor()
        if segs[0] == "monitor" or len(segs) < 2:
            raise _err(404, "not_found")
        if segs[0] != self.config.network:
            raise _err(404, "unknown_network")
        rest = segs[1:]
        if rest == ["summary"]:
            self._method(method, "GET")
            return self._summary(today)
        if rest == ["runners"]:
            self._method(method, "GET")
            return self._runners(query, today)
        if rest[0] == "runners" and len(rest) == 2:
            self._method(method, "GET")
            return self._runner(rest[1].lower(), today)
        if rest[0] == "runners" and len(rest) == 3 and rest[2] == "history":
            self._method(method, "GET")
            return self._history(rest[1].lower(), query)
        if rest == ["epochs"]:
            self._method(method, "GET")
            return {"items": [self._epoch_row(e) for e in self.store.list_epochs()]}
        if rest[0] == "epochs" and len(rest) == 2:
            self._method(method, "GET")
            return self._epoch(rest[1])
        raise _err(404, "not_found")

    @staticmethod
    def _method(method, allowed):
        if method != allowed:
            raise _err(405, "method_not_allowed", {"Allow": allowed})

    # ---- handlers ----
    def _monitor(self):
        tip = None
        if self.chain is not None:
            try:
                n, h = self.chain.tip()
                tip = {"number": n, "hash": h}
            except Exception:
                tip = None
        now = self.clock()

        def meta_int(key):
            try:
                return int(float(self.store.get_meta(key)))
            except (TypeError, ValueError):
                return None
        clock_ms = meta_int("clock_ms")
        spare = meta_int("config_cell_spare_shannons")
        return {"registry_last_scan_at": meta_int("registry_last_scan_at"),
                "clock_ms": clock_ms,
                "clock_age_s": None if clock_ms is None else int(now - clock_ms / 1000),
                "config_cell_spare_ckb": None if spare is None else spare // 10**8,
                "crosscheck": self.cross.status if self.cross is not None else "off",
                "pubkey": self.pubkey, "version": self.version,
                "score_formula": scoring.SCORE_FORMULA, "network": self.config.network,
                "public_url": self.config.public_url, "tip": tip,
                "paused": bool(getattr(self.prober, "paused", False)),
                "stat_cell_type_hash": self.store.get_meta("stat_cell_type_hash"),
                "csr_config_type_hash": configcell.config_hash_of(self.config),
                "csr_registry_type_hash": configcell.registry_hash_of(self.config),
                "csr_registry_code_hash": self.config.csr_registry_code_hash or None,
                "p2p_address": self.config.p2p_public_address or None}

    def _runners(self, query, today):
        limit = 50
        if "limit" in query:
            try:
                limit = int(query["limit"][0])
            except ValueError:
                raise _err(400, "bad_limit") from None
            if not 1 <= limit <= 500:
                raise _err(400, "bad_limit")
        offset = 0
        if "cursor" in query:
            try:
                offset = int(base64.urlsafe_b64decode(query["cursor"][0].encode("ascii")).decode())
                if offset < 0:
                    raise ValueError
            except (ValueError, UnicodeError):
                raise _err(400, "bad_cursor") from None
        ranking = self._ranking(today)
        page = ranking[offset:offset + limit]
        nxt = None
        if offset + limit < len(ranking):
            nxt = base64.urlsafe_b64encode(str(offset + limit).encode()).decode()
        return {"network": self.config.network, "score_formula": scoring.SCORE_FORMULA,
                "date": today, "items": [{k: i[k] for k in _RANK_KEYS} for i in page],
                "next_cursor": nxt}

    def _active_runner(self, rid):
        r = self.store.get_runner(rid)
        if r is None or r["status"] != "active":
            raise _err(404, "unknown_runner")
        return r

    def _runner(self, rid, today):
        r = self._active_runner(rid)
        item = next((i for i in self._ranking(today) if i["runner_id"] == rid), None)
        if item is None:
            raise _err(404, "unknown_runner")
        lp = self.store.last_probe(rid)
        p2p = self.store.last_p2p_check(rid)
        return {
            "runner_id": rid, "rank": item["rank"], "score": item["score"],
            "provisional": item["provisional"], "status": r["status"], "flags": item["flags"],
            "metrics": {k: item[k] for k in
                        ("a7", "a30", "a365", "s30", "f30", "t", "median_lag_30")},
            "first_seen": int(r["first_seen"]), "first_seen_day": day_of(r["first_seen"]),
            "last_seen": r["last_seen"],
            "registration": {"service_pubkey": r["service_pubkey"], "peer_id": r["peer_id"],
                             "mode": r["mode"], "has_endpoint": bool(r["endpoint"]),
                             "reg_outpoint": r["reg_outpoint"]},
            "country": r["country"], "region": r["region"], "asn": r["asn"],
            "asn_peers": item["asn_peers"], "csr_version": r["csr_version"],
            "ckb_version": r["ckb_version"],
            "last_probe": None if lp is None else {
                "ts": lp["ts"], "result": lp["result"], "failure_reason": lp["failure_reason"]},
            "last_p2p_check": None if p2p is None else {"ts": p2p["ts"], "result": p2p["result"]},
            "check_type": self._check_type(r),
            "identity_proven_at": r.get("identity_proven_at"),
            "unranked_reason": item["unranked_reason"],
        }

    def _history(self, rid, query):
        self._active_runner(rid)
        bucket = query.get("bucket", ["hour"])[0]
        if bucket not in ("hour", "day"):
            raise _err(400, "bad_bucket")
        try:
            to = int(query["to"][0]) if "to" in query else int(self.clock())
            frm = int(query["from"][0]) if "from" in query else to - 7 * 86400
        except ValueError:
            raise _err(400, "bad_range") from None
        limit = int(self.clock()) + 86400
        if not (0 <= frm <= limit and 0 <= to <= limit):
            raise _err(400, "bad_request")
        if to < frm or to - frm > 400 * 86400:
            raise _err(400, "bad_range")
        items = []
        if bucket == "hour":
            groups = {}
            for p in self.store.probes(rid, since=frm, until=to):
                if p["result"] == "excluded":
                    continue
                groups.setdefault(p["ts"] // 3600 * 3600, []).append(p)
            for start in sorted(groups):
                ps = groups[start]
                items.append({
                    "start": start, "probes_total": len(ps),
                    "probes_ok": sum(1 for p in ps if p["result"] == "ok"),
                    "in_sync": sum(1 for p in ps if p["in_sync"]),
                    "median_lag": _median([p["lag"] for p in ps if p["lag"] is not None])})
        else:
            for r in self.store.daily_stats(rid, day_of(frm), day_of(to)):
                items.append({"start": day_start(r["day"]), "day": r["day"],
                              **{k: r[k] for k in ("probes_total", "probes_ok", "in_sync",
                                                   "median_lag", "p2p_total", "p2p_ok", "score")}})
        return {"runner_id": rid, "bucket": bucket, "from": frm, "to": to, "items": items}

    @staticmethod
    def _epoch_row(e):
        return {k: e[k] for k in ("epoch", "start", "end", "merkle_root", "stat_cell_tx")}

    def _epoch(self, n):
        e = self.store.get_epoch(int(n)) if n.isascii() and n.isdigit() else None
        if e is None:
            raise _err(404, "not_found" if not (n.isascii() and n.isdigit()) else "unknown_epoch")
        return {**e["summary"], **self._epoch_row(e)}

    def _check_type(self, runner):
        """p2p_verified: the daily check through our node passed within 48 h; peer_connected: a
        successful probe of the last 24 h came from a peer our node is connected to."""
        now = self.clock()
        last = self.store.last_p2p_check(runner["runner_id"])
        if last is not None and last["result"] == "ok" and now - last["ts"] <= P2P_VERIFIED_S:
            return "p2p_verified"
        probes = self.store.probes(runner["runner_id"], since=now - 86400)
        if any(p["result"] == "ok" and p["p2p_verified"] for p in probes):
            return "peer_connected"
        return "challenge_only"

    def _post_csr(self, name, body, ip):
        if len(body) > MAX_BODY:
            raise _err(413, "too_large")
        target = self.attester if name == "attest" else self.prober
        if target is None:
            raise _err(503, "unavailable")
        try:
            obj = json.loads(body.decode("utf-8"))
        except (ValueError, UnicodeError):
            raise _err(400, "bad_request") from None
        fn = {"checkin": "handle_checkin", "answer": "handle_answer",
              "attest": "handle_attest", "identity": "handle_identity"}[name]
        status, out = getattr(target, fn)(obj, ip, self.clock())
        return self._raise_or(status, out)

    def _cached(self, name, build):
        now = self.clock()
        with self._lock:
            hit = self._cache.get(name)
            if hit and 0 <= now - hit[0] < CACHE_TTL_S:
                return hit[1]
        value = build()
        with self._lock:
            self._cache[name] = (now, value)
        return value

    def _network(self):
        return self._cached("network", self._build_network)

    def _locations(self):
        return self._cached("locations", self._build_locations)

    def _build_network(self):
        now = self.clock()
        runners = self.store.list_runners()
        reachable = self.store.reachable_count(now - self.config.reachable_window_s)
        counts = {}
        for r in runners:
            c = r["country"]
            if c and c != "??":
                counts[c] = counts.get(c, 0) + 1
        countries = [{"code": c, "count": n} for c, n in
                     sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))]
        return {"nodes_total": len(runners), "nodes_reachable": reachable,
                "countries": countries, "updated_at": int(now)}

    def _build_locations(self):
        runners = self.store.list_runners()
        cells = {}
        located = 0
        for r in runners:
            lat, lon = r.get("loc_lat"), r.get("loc_lon")
            if lat is None or lon is None or r["country"] in (None, "", "??"):
                continue
            located += 1
            cells[(int(lat), int(lon))] = cells.get((int(lat), int(lon)), 0) + 1
        locations = [{"lat": la, "lon": lo, "count": n} for (la, lo), n in
                     sorted(cells.items(), key=lambda kv: (-kv[1], -kv[0][0], kv[0][1]))]
        return {"locations": locations, "located": located, "unlocated": len(runners) - located,
                "grid_deg": geo.GRID_DEG, "updated_at": int(self.clock())}

    def _node(self, peer_id, today):
        r = self.store.find_runner_by_peer(peer_id)
        st = self.store.stake_for(peer_id)
        if r is None and st is None:
            raise _err(404, "unknown_node")
        ranking = self._ranking(today)
        item = None if r is None else next(
            (i for i in ranking if i["runner_id"] == r["runner_id"]), None)
        now = self.clock()
        if r is None:
            check_type, last_at = "none", 0
        else:
            lp = self.store.last_probe(r["runner_id"])
            check_type = self._check_type(r)
            last_at = int(lp["ts"]) if lp else 0
        reg = self.store.registration_for(peer_id)
        if reg is None:
            att = {"status": "none", "expiry": None}
        else:
            att = {"status": "valid" if reg["expiry_ms"] > now * 1000 else "expired",
                   "expiry": reg["expiry_ms"] // 1000}
        stake = ({"status": "none", "capacity_ckb": None, "outpoint": None} if st is None else
                 {"status": st["status"], "capacity_ckb": st["capacity_ckb"],
                  "outpoint": st["stake_outpoint"]})
        if item is None:
            avail = {"d7": None, "d30": None, "d365": None}
        else:
            avail = {"d7": round(item["a7"], 4), "d30": round(item["a30"], 4),
                     "d365": round(item["a365"], 4)}
        return {"peer_id": peer_id, "rank": None if item is None else item.get("rank"),
                "of": sum(1 for i in ranking if i.get("rank") is not None),
                "provisional": bool(item and item.get("provisional")),
                "availability": avail, "check_type": check_type,
                "attestation": att, "stake": stake, "last_check_at": last_at}

    @staticmethod
    def _raise_or(status, out):
        if status != 200:
            raise _Reply(status, out)
        return out


class ApiServer:
    def __init__(self, api, host, port, *, timeout_s=10, max_connections=64):
        self.api = api
        slots = threading.BoundedSemaphore(max_connections)
        busy = (b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n"
                b"Content-Length: 0\r\n\r\n")

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = timeout_s

            def _serve(self):
                try:
                    n = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    n = 0
                body = self.rfile.read(min(max(n, 0), MAX_BODY + 1)) if n > 0 else b""
                status, hdrs, out = api.handle(self.command, self.path, dict(self.headers.items()),
                                               body, self.client_address[0])
                self.send_response(status)
                for k, v in hdrs.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(out)))
                if n > MAX_BODY + 1:
                    self.send_header("Connection", "close")
                    self.close_connection = True
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(out)

            do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _serve

            def log_message(self, *args):
                pass

        class Server(ThreadingHTTPServer):
            def process_request(self, request, client_address):
                if not slots.acquire(blocking=False):
                    try:
                        request.settimeout(1)
                        request.sendall(busy)
                    except OSError:
                        pass
                    self.shutdown_request(request)
                    return
                super().process_request(request, client_address)

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    slots.release()

        self.httpd = Server((host, port), Handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self._thread = None

    def start(self):
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        if self._thread:
            self._thread.join(5)
