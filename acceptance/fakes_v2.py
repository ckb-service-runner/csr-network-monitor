"""Shared fakes for the v2 phases (CSR ping protocol, discovery, on-chain registry).

FakeChainV2   FakeChain plus get_peers()
peer_entry    one entry of the CKB `get_peers` RPC result
FakeCSR       a CSR node: answers POST /v1/challenge (inbound) and can check in (outbound),
              following spec/ping-protocol.md of ckb-service-runner
"""
import json
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from csrmon import crypto, ping
from csrmon.hashing import to_hex
from fakes import FakeChain, block_hash


class FakeChainV2(FakeChain):
    def __init__(self, tip=100_000):
        super().__init__(tip)
        self.peers = []

    def get_peers(self):
        self._check()
        return self.peers


def peer_entry(node_id, addresses):
    return {"node_id": node_id, "version": "0.210.0", "is_outbound": True,
            "addresses": [{"address": a, "score": "0x1"} for a in addresses],
            "connected_duration": "0x3e8", "protocols": []}


class FakeCSR:
    """A CSR node. `monitor_pubkey` is the key it trusts (hex)."""

    def __init__(self, service_secret, peer_id, chain, monitor_pubkey, *, network="testnet",
                 lag=1, r2_state="Synced", wrong_block=False, delay=0.0, status=None,
                 clock=time.time):
        self.secret, self.peer_id, self.chain = service_secret, peer_id, chain
        self.monitor_pubkey, self.network = monitor_pubkey, network
        self.lag, self.r2_state, self.wrong_block = lag, r2_state, wrong_block
        self.delay, self.status, self.clock = delay, status, clock
        self.service_pubkey = to_hex(crypto.pubkey_from_secret(service_secret))
        self.used_nonces = set()
        self.received = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.received.append((self.path, raw))
                if outer.delay:
                    time.sleep(outer.delay)
                if self.path != "/v1/challenge":
                    return self._send(404, b"not found")
                if outer.status:
                    return self._send(outer.status, b"forced")
                try:
                    ch = json.loads(raw)
                except Exception:
                    return self._send(400, b"malformed challenge")
                code, body = outer.respond(ch)
                self._send(code, json.dumps(body).encode() if code == 200 else body.encode(),
                           "application/json" if code == 200 else "text/plain")

            def _send(self, code, data, ctype="text/plain"):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    # CSR's checks (spec §4), in CSR's order
    def respond(self, ch):
        if not isinstance(ch, dict) or set(ch) != {"nonce", "height", "issued_at", "monitor_sig"}:
            return 400, "malformed challenge"
        if not ping.valid_nonce(ch["nonce"]):
            return 400, "invalid nonce"
        if not ping.verify_challenge(ch, self.monitor_pubkey):
            return 403, "invalid monitor signature"
        if abs(int(self.clock()) - ch["issued_at"]) > ping.FRESHNESS_S:
            return 400, "challenge not fresh"
        tip = self.chain.tip_number - self.lag
        if ch["height"] > tip:
            return 400, "height above tip"
        if ch["nonce"] in self.used_nonces:
            return 409, "nonce already answered"
        self.used_nonces.add(ch["nonce"])
        return 200, self.answer(ch)

    def answer(self, ch, ping_mode="inbound"):
        tip = self.chain.tip_number - self.lag
        bh = "0x" + "00" * 32 if self.wrong_block else block_hash(ch["height"])
        return ping.make_answer(self.secret, ch, peer_id=self.peer_id, network=self.network,
                                csr_version="0.1.0", node_version="0.210.0", r2_state=self.r2_state,
                                tip_number=tip, tip_hash=block_hash(tip), block_hash_at_height=bh,
                                uptime_s=3600, ping_mode=ping_mode)

    def checkin_body(self):
        return {"peer_id": self.peer_id, "service_pubkey": self.service_pubkey,
                "binding_sig": ping.sign(self.secret, ping.binding_message(
                    self.peer_id, self.service_pubkey, self.network)),
                "network": self.network, "csr_version": "0.1.0"}

    def checkin_over_http(self, monitor_url):
        """Outbound flow (spec §5): returns (status of /v1/answer, reply body)."""
        status, reply = _post(monitor_url + "/v1/checkin", self.checkin_body())
        if status != 200:
            return status, reply
        code, body = self.respond(reply["challenge"])
        if code != 200:
            return code, body
        body["answer"]["ping_mode"] = "outbound"
        body["sig"] = ping.sign(self.secret, ping.answer_message(body["answer"]))
        return _post(monitor_url + "/v1/answer", body)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()


def _post(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw.decode(errors="replace")
