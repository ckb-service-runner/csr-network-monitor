"""CKB JSON-RPC client (ChainView implementation) and tip cross-check."""
import json
import urllib.request


class RpcError(Exception):
    pass


class RpcChain:
    def __init__(self, url, timeout=10):
        self.url = url
        self.timeout = timeout
        self._id = 0

    def call(self, method, params):
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method,
                           "params": params}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except Exception as e:
            raise RpcError(f"{method}: {type(e).__name__}: {e}") from None
        try:
            msg = json.loads(raw)
        except ValueError:
            raise RpcError(f"{method}: bad JSON in response") from None
        if not isinstance(msg, dict):
            raise RpcError(f"{method}: bad response")
        if msg.get("error"):
            raise RpcError(f"{method}: {msg['error']}")
        if "result" not in msg:
            raise RpcError(f"{method}: no result")
        return msg["result"]

    def tip(self):
        h = self.call("get_tip_header", [])
        try:
            return int(h["number"], 16), h["hash"]
        except (KeyError, TypeError, ValueError):
            raise RpcError("get_tip_header: malformed header") from None

    def block_hash(self, number):
        return self.call("get_block_hash", [hex(number)])

    def header(self, number):
        h = self.call("get_header_by_number", [hex(number)])
        if h is None:
            return None
        try:
            return {"number": int(h["number"], 16), "hash": h["hash"],
                    "timestamp_ms": int(h["timestamp"], 16)}
        except (KeyError, TypeError, ValueError):
            raise RpcError("get_header_by_number: malformed header") from None

    def block_at_time(self, ts_ms):
        tip, _ = self.tip()
        lo, hi = 0, tip
        g = self.header(0)
        if g is None or g["timestamp_ms"] > ts_ms:
            return 0
        # invariant: header(lo).timestamp <= ts_ms
        while lo < hi:
            mid = (lo + hi + 1) // 2
            h = self.header(mid)
            if h is not None and h["timestamp_ms"] <= ts_ms:
                lo = mid
            else:
                hi = mid - 1
        return lo

    def get_cells(self, script, script_type="type", exact=False):
        key = {"script": script, "script_type": script_type,
               "script_search_mode": "exact" if exact else "prefix"}
        cursor = None
        while True:
            page = self.call("get_cells", [key, "asc", hex(100), cursor])
            objects = page.get("objects") or []
            if not objects:
                return
            yield from objects
            cursor = page.get("last_cursor")
            if not cursor or cursor == "0x":
                return

    def send_transaction(self, tx):
        return self.call("send_transaction", [tx, "passthrough"])


class TipCrossCheck:
    def __init__(self, local, remote, threshold):
        self.local, self.remote, self.threshold = local, remote, threshold

    def check(self) -> bool:
        try:
            local_tip = self.local.tip()[0]
        except Exception:
            return False
        if self.remote is None:
            return True
        try:
            remote_tip = self.remote.tip()[0]
        except Exception:
            return True
        return abs(remote_tip - local_tip) <= self.threshold
