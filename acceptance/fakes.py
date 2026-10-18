"""Shared test fakes (written by the spec author, used by phases 4-12).

FakeChain      in-memory implementation of the ChainView interface
FakeRpcServer  JSON-RPC server on 127.0.0.1 that imitates the CKB node RPC
FakeRunner     HTTP server that answers /csr/v1/probe like a CSR runner
make_registration_cell  builds a registration cell as the indexer returns it
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from csrmon import crypto, protocol
from csrmon.hashing import ckb_blake2b, to_hex

GENESIS_MS = 1_700_000_000_000
BLOCK_MS = 8_000

REG_CODE_HASH = "0x" + "5e" * 32
REG_SCRIPT = {"code_hash": REG_CODE_HASH, "hash_type": "type", "args": "0x"}


def block_hash(n):
    return to_hex(ckb_blake2b(b"block" + int(n).to_bytes(8, "little")))


def block_ts(n):
    return GENESIS_MS + int(n) * BLOCK_MS


def _hx(n):
    return hex(int(n))


def _script_matches(search, script, mode="prefix"):
    if script is None:
        return False
    if script["code_hash"].lower() != search["code_hash"].lower():
        return False
    if script["hash_type"] != search["hash_type"]:
        return False
    if mode == "exact":
        return script["args"].lower() == search["args"].lower()
    return script["args"].lower().startswith(search["args"].lower())


class FakeChain:
    """Same interface as csrmon.chain.RpcChain, without any network."""

    def __init__(self, tip=100_000):
        self.tip_number = tip
        self.cells = []          # indexer cell objects (RPC JSON shape)
        self.sent = []           # transactions passed to send_transaction
        self.forked = {}         # height -> alternative hash returned by block_hash
        self.fail = False
        self.on_send = None      # optional callback(tx) -> tx_hash

    def _check(self):
        if self.fail:
            from csrmon.chain import RpcError
            raise RpcError("fake chain down")

    def tip(self):
        self._check()
        return self.tip_number, self.block_hash(self.tip_number)

    def block_hash(self, number):
        self._check()
        if number < 0 or number > self.tip_number:
            return None
        return self.forked.get(number, block_hash(number))

    def header(self, number):
        h = self.block_hash(number)
        if h is None:
            return None
        return {"number": number, "hash": h, "timestamp_ms": block_ts(number)}

    def block_at_time(self, ts_ms):
        self._check()
        n = (ts_ms - GENESIS_MS) // BLOCK_MS
        return max(0, min(self.tip_number, n))

    def get_cells(self, script, script_type="type", exact=False):
        self._check()
        for c in list(self.cells):
            target = c["output"]["type"] if script_type == "type" else c["output"]["lock"]
            if _script_matches(script, target, "exact" if exact else "prefix"):
                yield c

    def send_transaction(self, tx):
        self._check()
        self.sent.append(tx)
        if self.on_send:
            return self.on_send(tx)
        return to_hex(ckb_blake2b(json.dumps(tx, sort_keys=True).encode()))


def cell(type_script, data_hex, tx_hash, index=0, capacity=500 * 10**8, lock=None, block=1):
    return {
        "output": {"capacity": _hx(capacity),
                   "lock": lock or {"code_hash": "0x" + "01" * 32, "hash_type": "type", "args": "0x"},
                   "type": type_script},
        "output_data": data_hex,
        "out_point": {"tx_hash": tx_hash, "index": _hx(index)},
        "block_number": _hx(block),
        "tx_index": "0x0",
    }


def make_registration_cell(service_secret, p2p_secret, *, network="testnet", mode="pull",
                           endpoint="https://runner.example.org", p2p_port=8115,
                           ranking_opt_in=True, tx_byte=0x10, block=1, bind_network=None):
    svc_pk = crypto.pubkey_from_secret(service_secret)
    reg = protocol.Registration(
        network=network, mode=mode, ranking_opt_in=ranking_opt_in, service_pubkey=svc_pk,
        p2p_pubkey=crypto.pubkey_from_secret(p2p_secret),
        bind_sig=protocol.sign_bind(p2p_secret, svc_pk, bind_network or network),
        p2p_port=p2p_port, endpoint=endpoint)
    data = protocol.encode_registration(reg)
    return cell(dict(REG_SCRIPT), to_hex(data), "0x" + f"{tx_byte:02x}" * 32, block=block), reg


class FakeRpcServer:
    """Imitates the CKB JSON-RPC methods the monitor uses."""

    def __init__(self, chain=None, page_limit=None):
        self.chain = chain or FakeChain()
        self.calls = []
        self.page_limit = page_limit
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.calls.append(body["method"])
                try:
                    result = outer.dispatch(body["method"], body.get("params", []))
                    resp = {"jsonrpc": "2.0", "id": body.get("id"), "result": result}
                except KeyError:
                    resp = {"jsonrpc": "2.0", "id": body.get("id"),
                            "error": {"code": -32601, "message": "Method not found"}}
                except ValueError as e:
                    resp = {"jsonrpc": "2.0", "id": body.get("id"),
                            "error": {"code": -3, "message": str(e)}}
                data = json.dumps(resp).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _header(self, n):
        c = self.chain
        h = c.forked.get(n, block_hash(n))
        return {"number": _hx(n), "hash": h, "timestamp": _hx(block_ts(n)),
                "epoch": "0x0", "parent_hash": block_hash(n - 1) if n else "0x" + "00" * 32}

    def dispatch(self, method, params):
        c = self.chain
        if method == "get_tip_header":
            return self._header(c.tip_number)
        if method == "get_block_hash":
            n = int(params[0], 16)
            return c.block_hash(n)
        if method == "get_header_by_number":
            n = int(params[0], 16)
            return self._header(n) if 0 <= n <= c.tip_number else None
        if method == "get_cells":
            key, order, limit, cursor = params
            limit = int(limit, 16)
            if self.page_limit:
                limit = min(limit, self.page_limit)
            mode = key.get("script_search_mode", "prefix")
            matches = [x for x in c.cells
                       if _script_matches(key["script"],
                                          x["output"]["type" if key["script_type"] == "type" else "lock"],
                                          mode)]
            start = int(cursor, 16) if cursor else 0
            page = matches[start:start + limit]
            return {"objects": page, "last_cursor": _hx(start + len(page))}
        if method == "send_transaction":
            if params[1] != "passthrough":
                raise ValueError("outputs validator")
            return c.send_transaction(params[0])
        if method == "fail_please":
            raise ValueError("boom")
        raise KeyError(method)


class FakeRunner:
    """HTTP runner answering POST /csr/v1/probe with a signed response."""

    def __init__(self, service_secret, p2p_secret, chain, *, delay=0.0, lag=1,
                 wrong_block=False, status=200, garbage=False):
        self.secret = service_secret
        self.peer_id = protocol.peer_id_from_pubkey(crypto.pubkey_from_secret(p2p_secret))
        self.chain = chain
        self.delay, self.lag, self.wrong_block = delay, lag, wrong_block
        self.status, self.garbage = status, garbage
        self.received = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                import time
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.received.append((self.path, body))
                if outer.delay:
                    time.sleep(outer.delay)
                if self.path != "/csr/v1/probe":
                    self.send_response(404)
                    self.end_headers()
                    return
                data = b"not json" if outer.garbage else json.dumps(outer.answer(body)).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def answer(self, challenge):
        tip = self.chain.tip_number - self.lag
        bh = block_hash(challenge["block_height"])
        if self.wrong_block:
            bh = "0x" + "00" * 32
        return protocol.sign_response(
            self.secret, challenge, peer_id=self.peer_id, tip_number=tip,
            tip_hash=block_hash(tip), block_hash=bh, ibd=False, peers_out=8,
            csr_version="0.1.0", ckb_version="0.203.0")

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()
