"""External P2P full-node check: runs a helper command and verifies the block hashes it reports."""
import ipaddress
import json
import random
import shlex
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit


class P2PError(Exception):
    pass


def choose_heights(tip, rng, count_recent=2, count_old=2, recent_window=1000) -> list[int]:
    heights = set()
    lo = max(1, tip - recent_window + 1)
    if tip >= lo:
        n = tip - lo + 1
        heights.update(rng.sample(range(lo, tip + 1), min(count_recent, n)))
    old_hi = tip - recent_window
    if old_hi >= 1:
        heights.update(rng.sample(range(1, old_hi + 1), min(count_old, old_hi)))
    return sorted(heights)


def address_for(runner):
    port = runner.get("p2p_port") or 0
    endpoint = runner.get("endpoint")
    if runner.get("mode") != "pull" or port <= 0 or not endpoint:
        return None
    try:
        host = urlsplit(endpoint).hostname
    except ValueError:
        return None
    if not host:
        return None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return f"/dns4/{host}/tcp/{port}"
    return f"/ip{ip.version}/{ip}/tcp/{port}"


class P2PChecker:
    def __init__(self, cmd, timeout_s, network):
        self.cmd = cmd
        self.timeout_s = timeout_s
        self.network = network

    def run(self, request: dict) -> dict:
        try:
            argv = shlex.split(self.cmd)
            if not argv:
                raise P2PError("empty p2p check command")
            proc = subprocess.run(argv, input=json.dumps(request), capture_output=True,
                                  text=True, timeout=self.timeout_s)
        except subprocess.TimeoutExpired:
            raise P2PError("p2p helper timed out") from None
        except (OSError, ValueError) as e:
            raise P2PError(f"cannot start p2p helper: {type(e).__name__}") from None
        if proc.returncode != 0:
            raise P2PError(f"p2p helper exited with {proc.returncode}")
        try:
            out = json.loads(proc.stdout)
        except ValueError:
            raise P2PError("p2p helper output is not JSON") from None
        if not isinstance(out, dict) or not isinstance(out.get("served"), list):
            raise P2PError("p2p helper output has no 'served' list")
        return out


def run_p2p_check(store, chain, checker, runner, *, now, rng) -> dict:
    rid = runner["runner_id"]
    heights = choose_heights(chain.tip()[0], rng)
    request = {"v": 1, "network": checker.network, "peer_id": runner["peer_id"],
               "address": address_for(runner), "heights": heights,
               "timeout_s": checker.timeout_s}
    seen, served, latency = None, 0, None
    try:
        out = checker.run(request)
    except P2PError:
        result = "error"
    else:
        seen = out.get("peer_id_seen")
        if not isinstance(seen, str):
            seen = None
        lat = out.get("latency_ms")
        latency = lat if isinstance(lat, int) and not isinstance(lat, bool) else None
        good = set()
        for item in out["served"]:
            if isinstance(item, dict) and isinstance(item.get("height"), int):
                good.add((item["height"], str(item.get("hash", "")).lower()))
        served = sum(1 for h in heights if (h, str(chain.block_hash(h)).lower()) in good)
        if seen is not None and seen != runner["peer_id"]:
            result = "identity_mismatch"
        elif seen is None or served != len(heights):
            result = "fail"
        else:
            result = "ok"
    if result == "identity_mismatch":
        store.set_flag(rid, "identity_mismatch", True)
    elif result == "ok":
        store.set_flag(rid, "identity_mismatch", False)
    store.record_p2p_check(rid, ts=now, heights=heights, served=served, latency_ms=latency,
                           peer_id_seen=seen, result=result)
    return {"runner_id": rid, "result": result, "served": served, "peer_id_seen": seen,
            "heights": heights}


class P2PScheduler:
    def __init__(self, store, chain, checker, config, rng=None, clock=time.time):
        self.store = store
        self.chain = chain
        self.checker = checker
        self.config = config
        self.rng = rng or random.Random()
        self.clock = clock
        self._planned = {}
        self._lock = threading.Lock()

    def _plan(self, rid, period, start, P):
        key = (rid, period)
        with self._lock:
            if key not in self._planned:
                self._planned[key] = start + 0.05 * P + self.rng.uniform(0, 0.85 * P)
            return self._planned[key]

    def run_due(self, now=None) -> list:
        if self.checker is None:
            return []
        now = self.clock() if now is None else now
        P = self.config.p2p_interval_s
        period = int(now // P)
        start = period * P
        due = []
        for r in self.store.list_runners(("active",)):
            planned = self._plan(r["runner_id"], period, start, P)
            if now < planned:
                continue
            last = self.store.last_p2p_check(r["runner_id"])
            if last is not None and last["ts"] >= start:
                continue
            due.append(r)
        if not due:
            return []
        seeds = [self.rng.random() for _ in due]

        def work(args):
            r, seed = args
            return run_p2p_check(self.store, self.chain, self.checker, r, now=int(now),
                                 rng=random.Random(seed))

        with ThreadPoolExecutor(max_workers=4) as ex:
            return list(ex.map(work, zip(due, seeds)))
