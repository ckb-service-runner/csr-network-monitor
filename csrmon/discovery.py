"""Peer discovery: turn the CKB node's get_peers into candidate CSR endpoints."""
import ipaddress

from .netutil import public_ip


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


class Discovery:
    def __init__(self, store, config):
        self.store, self.config = store, config

    def due(self, peers, now) -> list:
        runners = self.store.list_runners(("active",))
        peer_ids = {r["peer_id"] for r in runners if r["peer_id"]}
        endpoints = {r["endpoint"] for r in runners if r["endpoint"]}
        out = []
        for p in peers:
            if not (self.config.allow_insecure_endpoints or public_ip(p["ip"])):
                continue
            ep = endpoint_for(p["ip"], self.config.ping_port)
            if p["node_id"] in peer_ids or ep in endpoints:
                continue
            d = self.store.discovery_get(p["ip"])
            if (d and d["last_try"] > now - self.config.discovery_backoff_s
                    and (d["last_ok"] is None or d["last_ok"] < d["last_try"])):
                continue
            out.append({"node_id": p["node_id"], "ip": p["ip"], "endpoint": ep})
        return out
