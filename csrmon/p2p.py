"""Node identity: P2P-key proofs and the daily check of each runner's peer through the monitor's own node."""
import hashlib
import ipaddress
import os
import random
import time
from urllib.parse import urlsplit

from .base58 import b58encode
from .schedule import _unit, schedule_secret
from .scoring import IDENTITY_PROOF_MAX_AGE_S


IDENTITY_PREFIX = "CSR-NODE-IDENTITY-v1"


def peer_id_from_pubkey(pk: bytes) -> str:
    """libp2p peer ID of a secp256k1 key as CKB derives it: base58(0x12 0x20 SHA-256(pubkey))."""
    return b58encode(b"\x12\x20" + hashlib.sha256(bytes(pk)).digest())


def identity_message(peer_id, service_pubkey, network, ts) -> str:
    return f"{IDENTITY_PREFIX}\n{peer_id}\n{service_pubkey}\n{network}\n{ts}"


def _hex_int(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 16)
        except ValueError:
            return None
    return None


def evaluate_peer(peers, peer_id, *, chain, sync_threshold) -> str:
    """Judge one runner's peer in the monitor node's `get_peers` result."""
    peer = next((p for p in peers or [] if isinstance(p, dict) and p.get("node_id") == peer_id), None)
    if peer is None:
        return "not_connected"
    ss = peer.get("sync_state")
    if not isinstance(ss, dict):
        return "not_connected"
    number = _hex_int(ss.get("best_known_header_number"))
    hsh = ss.get("best_known_header_hash")
    if number is None or not isinstance(hsh, str):
        return "not_connected"
    tip = chain.tip()[0]
    if number < tip - sync_threshold:
        return "behind"
    if number > tip + sync_threshold:
        return "wrong_chain"
    if number <= tip:
        expected = chain.block_hash(number)
        if expected is None or str(expected).lower() != hsh.lower():
            return "wrong_chain"
    return "ok"


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


class P2PScheduler:
    """Once per `p2p_interval_s` per active runner: is its peer connected to our node and on our chain?"""

    def __init__(self, store, chain, config, rng=None, clock=time.time, paused=None, secret=None):
        self.store = store
        self.chain = chain
        self.config = config
        self.rng = rng or random.Random()
        self.clock = clock
        self.paused = paused or (lambda: False)
        # Stateless plan (no growing map, F-SEC-012): a keyed hash of runner and period.
        self._schedule_key = schedule_secret(secret if secret is not None else os.urandom(32))

    def planned_time(self, rid, period):
        P = self.config.p2p_interval_s
        return period * P + 0.05 * P + _unit(self._schedule_key, f"{rid}:{period}") * 0.85 * P

    def due(self, now) -> list:
        P = self.config.p2p_interval_s
        period = int(now // P)
        start = period * P
        out = []
        for r in self.store.list_runners(("active",)):
            if not r["peer_id"] or now < self.planned_time(r["runner_id"], period):
                continue
            last = self.store.last_p2p_check(r["runner_id"])
            if last is not None and last["ts"] >= start:
                continue
            out.append(r)
        return out

    def _own_node_id(self):
        try:
            return self.chain.local_node_id()
        except Exception:  # noqa: BLE001 - unknown own ID: every runner is judged by get_peers
            return None

    @staticmethod
    def _is_own_node(runner, own, now) -> bool:
        """A runner on the monitor's own node never appears in its `get_peers`. It counts as
        verified when it proved that node's P2P key within the proof lifetime (the tip of that
        node is watched by the cross-check); a bare claim of the ID is judged as usual."""
        at = runner.get("identity_proven_at")
        return (own is not None and runner.get("peer_id") == own and at is not None
                and now - at <= IDENTITY_PROOF_MAX_AGE_S)

    def run_due(self, now=None) -> list:
        now = self.clock() if now is None else now
        if self.paused():
            return []
        due = self.due(now)
        if not due:
            return []
        ts = int(now)
        try:
            peers = self.chain.get_peers()
            if not isinstance(peers, list):
                raise ValueError("get_peers did not return a list")
            own = self._own_node_id()
            results = [(r, "ok" if self._is_own_node(r, own, ts) else
                        evaluate_peer(peers, r["peer_id"], chain=self.chain,
                                      sync_threshold=self.config.sync_threshold)) for r in due]
        except Exception as e:  # noqa: BLE001 - any node failure: record and wait for the next period
            reason = f"node_error: {type(e).__name__}"
            out = []
            for r in due:
                self.store.record_p2p_check(r["runner_id"], ts=ts, heights=[], served=0,
                                            latency_ms=None, peer_id_seen=None, result="error",
                                            reason=reason)
                out.append({"runner_id": r["runner_id"], "result": "error", "reason": reason})
            return out
        out = []
        for r, verdict in results:
            result = "ok" if verdict == "ok" else "fail"
            reason = None if verdict == "ok" else verdict
            seen = None if verdict == "not_connected" else r["peer_id"]
            self.store.record_p2p_check(r["runner_id"], ts=ts, heights=[], served=1 if seen else 0,
                                        latency_ms=None, peer_id_seen=seen, result=result,
                                        reason=reason)
            out.append({"runner_id": r["runner_id"], "result": result, "reason": reason})
        return out
