"""Outgoing HTTP: no proxies, no redirects, bounded answers, an overall deadline."""
import http.client
import ipaddress
import socket
import time
import urllib.error
import urllib.request


class FetchError(Exception):
    def __init__(self, message="", *, timed_out=False):
        super().__init__(message)
        self.timed_out = timed_out


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _build_opener():
    op = urllib.request.OpenerDirector()
    for h in (urllib.request.UnknownHandler(), urllib.request.HTTPHandler(),
              urllib.request.HTTPSHandler(), _NoRedirect(),
              urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        op.add_handler(h)
    return op


def _read_limited(resp, max_bytes, deadline):
    chunks, total = [], 0
    while True:
        if time.monotonic() > deadline:
            raise FetchError("deadline exceeded", timed_out=True)
        chunk = resp.read(min(8192, max_bytes + 1 - total))
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > max_bytes:
            raise FetchError("answer too large")
        chunks.append(chunk)


def fetch_status(url, data=None, *, timeout=5, max_bytes=4096, headers=None):
    """Return (status, body); a redirect is not followed and comes back as (3xx, b"")."""
    deadline = time.monotonic() + timeout
    hdrs = dict(headers or {})
    if data is not None:
        hdrs.setdefault("Content-Type", "application/json")
    try:
        req = urllib.request.Request(url, data=data, headers=hdrs,
                                     method="POST" if data is not None else "GET")
        try:
            resp = _build_opener().open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            resp = e
        with resp:
            status = resp.status if hasattr(resp, "status") else resp.code
            if 300 <= status < 400:
                # never followed: the caller sees the redirect status and no body
                return status, b""
            # the socket timeout bounds each read; the loop bounds the total time
            return status, _read_limited(resp, max_bytes, deadline)
    except FetchError:
        raise
    except (OSError, ValueError, http.client.HTTPException) as e:
        if isinstance(e, (socket.timeout, TimeoutError)) or (
                isinstance(e, urllib.error.URLError)
                and isinstance(e.reason, (socket.timeout, TimeoutError))):
            raise FetchError("timeout", timed_out=True) from None
        raise FetchError(f"{type(e).__name__}: {e}") from None


def fetch(url, data=None, *, timeout=5, max_bytes=4096, headers=None) -> bytes:
    """Return the body of a 2xx answer; anything else raises FetchError."""
    status, body = fetch_status(url, data, timeout=timeout, max_bytes=max_bytes, headers=headers)
    if not 200 <= status < 300:
        raise FetchError(f"HTTP {status}")
    return body


def public_ip(ip) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    if (a.is_private or a.is_loopback or a.is_link_local or a.is_unspecified or a.is_reserved
            or a.is_multicast):
        return False
    if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
        return False
    if a.version == 6 and (a in ipaddress.ip_network("fc00::/7")
                           or a in ipaddress.ip_network("fe80::/10")):
        return False
    return True
