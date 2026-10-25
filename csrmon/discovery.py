"""Peer discovery: turn the CKB node's get_peers into candidate CSR endpoints."""
import ipaddress
import socket
import urllib.parse

from . import protocol
from .hashing import from_hex


def _addr_ip(addr):
    if not isinstance(addr, str):
        return None
    parts = addr.split("/")
    if len(parts) < 3 or parts[0] != "" or parts[1] not in ("ip4", "ip6"):
        return None
    try:
        ip = ipaddress.ip_address(parts[2])
    except ValueError:
        return None
    if (parts[1] == "ip4") != (ip.version == 4):
        return None
    return str(ip)


def parse_peers(result) -> list:
    out, seen = [], set()
    if not isinstance(result, list):
        return out
    for p in result:
        if not isinstance(p, dict):
            continue
        node_id = p.get("node_id")
        if not isinstance(node_id, str) or not node_id or node_id in seen:
            continue
        addrs = p.get("addresses")
        if not isinstance(addrs, list):
            continue
        for a in addrs:
            ip = _addr_ip(a.get("address") if isinstance(a, dict) else a)
            if ip:
                seen.add(node_id)
                out.append({"node_id": node_id, "ip": ip})
                break
    return out


def endpoint_for(ip, port) -> str:
    return f"http://[{ip}]:{port}" if ":" in ip else f"http://{ip}:{port}"


def endpoint_ip(endpoint, allow_insecure=False, resolve=socket.getaddrinfo):
    """The address to probe for a registered `endpoint` (Registry v3, F-MON-014), or None
    when the endpoint is refused: http(s) only, no credentials, query or fragment, and every
    address the host resolves to must be public unless `allow_insecure_endpoints`."""
    if not isinstance(endpoint, str) or not endpoint or len(endpoint) > 512:
        return None
    try:
        u = urllib.parse.urlsplit(endpoint)
        host, _ = u.hostname, u.port
    except ValueError:
        return None
    if (u.scheme not in ("http", "https") or not host or u.username is not None
            or u.password is not None or u.query or u.fragment
            or any(ch.isspace() for ch in endpoint)):
        return None
    try:
        ips = [ipaddress.ip_address(host)]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(a[4][0].split("%")[0])
                   for a in resolve(host, None)]
        except (OSError, ValueError, UnicodeError):
            return None
    if not ips:
        return None
    if not allow_insecure and not all(ip.is_global and not ip.is_multicast for ip in ips):
        return None
    return str(ips[0])


class Discovery:
    def __init__(self, store, config):
        self.store, self.config = store, config

    def due(self, peers, now) -> list:
        runners = self.store.list_runners(("active",))
        peer_ids = {r["peer_id"] for r in runners if r["peer_id"]}
        endpoints = {r["endpoint"] for r in runners if r["endpoint"]}
        out = []
        for p in peers:
            ep = endpoint_for(p["ip"], self.config.ping_port)
            if p["node_id"] in peer_ids or ep in endpoints:
                continue
            d = self.store.discovery_get(p["ip"])
            if (d and d["last_try"] > now - self.config.discovery_backoff_s
                    and (d["last_ok"] is None or d["last_ok"] < d["last_try"])):
                continue
            out.append({"node_id": p["node_id"], "ip": p["ip"], "endpoint": ep})
        return out

    def registered(self, now, resolve=socket.getaddrinfo) -> list:
        """Registered runners with an `endpoint` that are not yet probed there: they are probed at
        that endpoint (pull mode) even when they are not peers of the monitor's node."""
        out, seen = [], set()
        for reg in self.store.registered_endpoints():
            if reg["peer_id"] in seen:
                continue
            seen.add(reg["peer_id"])
            ep = reg["endpoint"]
            try:
                rid = protocol.runner_id(from_hex(reg["service_pubkey"]))
            except Exception:
                continue
            r = self.store.get_runner(rid)
            if (r is not None and r["status"] == "active" and r["mode"] == "inbound"
                    and r["endpoint"] == ep):
                continue
            d = self.store.discovery_get(ep)
            if (d and d["last_try"] > now - self.config.discovery_backoff_s
                    and (d["last_ok"] is None or d["last_ok"] < d["last_try"])):
                continue
            ip = endpoint_ip(ep, self.config.allow_insecure_endpoints, resolve)
            if ip is None:
                continue
            out.append({"node_id": reg["peer_id"], "ip": ip, "endpoint": ep,
                        "service_pubkey": reg["service_pubkey"], "key": ep})
        return out
