"""Integration fix (Oct 2026): outgoing requests carry the monitor's own user agent."""
import http.server
import threading

from csrmon import __version__, netutil


def test_fetch_sends_monitor_user_agent():
    seen = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen["ua"] = self.headers.get("User-Agent")
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    t = threading.Thread(target=srv.handle_request, daemon=True)
    t.start()
    try:
        body = netutil.fetch(f"http://127.0.0.1:{srv.server_port}/", b"{}", timeout=5)
    finally:
        srv.server_close()
    assert body == b"{}"
    assert seen["ua"].startswith(f"csr-network-monitor/{__version__}")
