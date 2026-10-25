# Installation

## Requirements

- Linux or WSL2 with systemd, Python ≥ 3.11 (no pip packages needed at runtime).
- A **synced CKB full node** of the same network with JSON-RPC on localhost (`http://127.0.0.1:8114`) and the `Indexer` and `Chain` modules enabled. The monitor refuses non-loopback `node_rpc`.
- Optional: a second node or provider for the tip cross-check, geolocation CSV files.
- For the daily P2P check: the monitor's CKB node must accept inbound P2P connections from the internet (see "P2P address of the monitor node").

## Install

```sh
sudo useradd --system --home /var/lib/csr-network-monitor --shell /usr/sbin/nologin csrmon
sudo mkdir -p /opt/csr-network-monitor /etc/csr-network-monitor /var/lib/csr-network-monitor
sudo python3 -m venv /opt/csr-network-monitor/venv
sudo /opt/csr-network-monitor/venv/bin/pip install /path/to/csr-network-monitor
sudo cp config/monitor-testnet.toml /etc/csr-network-monitor/monitor-testnet.toml   # and edit
sudo chown -R csrmon: /var/lib/csr-network-monitor
sudo -u csrmon /opt/csr-network-monitor/venv/bin/csrmon check-config --config /etc/csr-network-monitor/monitor-testnet.toml
sudo -u csrmon /opt/csr-network-monitor/venv/bin/csrmon keygen --config /etc/csr-network-monitor/monitor-testnet.toml
sudo -u csrmon /opt/csr-network-monitor/venv/bin/csrmon init-db --config /etc/csr-network-monitor/monitor-testnet.toml
```

`keygen` prints the public key and its `blake160` (the lock args of the monitor address). The key file is created with mode 0600; back it up. `init-db` records `monitor_start`; monitor downtime before that or later never counts against runners.

## systemd

```sh
sudo cp deploy/csr-network-monitor@.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now csr-network-monitor@testnet
journalctl -u csr-network-monitor@testnet -f
```

The instance name selects `/etc/csr-network-monitor/monitor-<name>.toml`. Run `@mainnet` the same way (port 8481).

## Hostnames and Caddy

There is **one hostname per network**, because CSR's endpoints carry no network in the path. The testnet monitor is `monitor-testnet.vericell.net` (instance `@testnet`, port 8480); mainnet gets its own host (port 8481). Copy `deploy/Caddyfile.example` to `/etc/caddy/Caddyfile`, set your domain and reload: Caddy proxies the whole host (API, web page, `/v1/checkin`, `/v1/answer`, `/v1/attest`) to the instance. Caddy is a trusted proxy (`trusted_proxies`), the monitor then reads the client IP from `X-Forwarded-For`.

CSR nodes in inbound mode must be reachable on their **ping port 8131** (`POST /v1/challenge`); the monitor finds them through the P2P peers of its CKB node (`get_peers`). Nodes behind NAT use outbound mode and check in at the monitor's hostname.

## CSR contracts and config cell

The config cell belongs to the monitor. Deploy CSR's contracts with the monitor key so the cell's lock is the monitor's sighash lock:

```sh
csr-dev deploy-contracts   # run with the monitor key (see CSR's documentation)
```

Take the values from CSR's `deployments/testnet.json` and set them in the monitor config:

- `config_type_args` – Type ID args of the config cell
- `csr_registry_code_hash` – data2 hash of the `csr-registry` contract
- `stat_cell_sighash_dep_tx` – dep group tx of the secp256k1 sighash lock (needed to sign the clock updates)

Testnet values: `config_type_args = "0xa98e580e53599b845b54ca0471a80b5e19813a6a8c4758876b60a95df00e0e8e"`, `csr_registry_code_hash = "0x47fee83ea91eabdfc8827045f63fe051b8fee5c05b9280a35f42f2e3597d3f36"`, `stat_cell_sighash_dep_tx = "0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"`.

**Fund the config cell**: it must hold enough capacity for the cell itself plus the fee of every clock update (`clock_update_fee_shannons`, taken from its capacity, every `clock_update_interval_s`). Also fund the monitor address (`keygen` prints the `blake160`) if you use the stat cell. The monitor then keeps `clock_ms` current, scans registry cells and issues attestations.

## Geolocation

Download the free **DB-IP Lite** country and ASN CSV files and point `geo_country_csv` / `geo_asn_csv` at them. **MaxMind GeoLite2** CSVs must first be converted to the same columns (`start_ip,end_ip,value…` as in the DB-IP files: country code, or ASN and organisation). Without files all runners have country `??`. Only a salted hash of a runner IP is stored; IPs and endpoints are never exposed.

## Map locations

The map on the public page needs the **DB-IP City Lite** CSV (monthly release, free):

1. Download `dbip-city-lite-YYYY-MM.csv.gz` from db-ip.com and gunzip it.
2. Place it as `/var/lib/csr-network-monitor/geo/dbip-city-lite.csv`.
3. Set `geo_city_csv = "/var/lib/csr-network-monitor/geo/dbip-city-lite.csv"` in the monitor config and restart the service.

Coordinates are reduced to the centre of a 2° × 2° cell while the file is loaded; only that cell is stored per runner and published via `GET /v1/locations`. Without the file, runners are listed as "unknown" and do not appear on the map.

The data is licensed **CC BY 4.0**; the public page shows the required credit to DB-IP. Refresh the file monthly (replace it and restart). Memory use: the snapped, merged ranges take roughly 50–150 MB for the full file; loading takes some seconds at start-up.

## P2P address of the monitor node

Runners connect their CKB node to the monitor's node; once a day the monitor reads `get_peers` of its node and checks each runner's peer (see docs/PROTOCOL.md, "Daily P2P check"). For this:

1. Read the node ID and listen address of the monitor node:

   ```sh
   curl -s -H 'content-type: application/json' \
     -d '{"id":1,"jsonrpc":"2.0","method":"local_node_info","params":[]}' http://127.0.0.1:8114 \
     | jq '.result | {node_id, addresses}'
   ```

2. Build the public multiaddr from the **public** IP (or DNS name) and P2P port (default `8115`) and the `node_id`, e.g. `/ip4/203.0.113.10/tcp/8115/p2p/QmXyz…` (`/dns4/monitor.example.org/tcp/8115/p2p/QmXyz…` also works). Set it in the config and restart:

   ```toml
   p2p_public_address = "/ip4/203.0.113.10/tcp/8115/p2p/QmXyz..."
   ```

   It is published as `p2p_address` in `GET /v1/monitor`. The node ID changes if the node's `network/secret_key` changes; update the key then.
3. The node's P2P port must be reachable from the internet (firewall, port forward; in the forwarded topology below the VPS forwards `8115`).
4. Give the node enough slots for the runners: in `ckb.toml`, `[network] max_peers` and `max_outbound_peers` set the inbound capacity (`max_peers − max_outbound_peers`). Keep it comfortably above the number of runners plus normal peers, e.g. `max_peers = 250`, `max_outbound_peers = 8` for up to ~200 runners.

`require_identity_proof` stays `false` during the rollout; see docs/PROTOCOL.md, "Identity requirement and rollout".

## Tip cross-check

Every `crosscheck_interval_s` the monitor compares its node tip with `second_tip_source` (an independent node RPC). If the local node is unreachable or differs by more than `sync_threshold`, probing is paused; paused slots are `excluded`, never misses.

## Stat cell

1. Verify the stat cell values for your network in the config (ACP and sighash code hash and dep group, see the comments in the example config).
2. Take the `blake160` printed by `keygen`, build the address with the sighash lock and send enough CKB (more than `stat_cell_capacity_ckb` plus fees) to it.
3. Set `stat_cell_enabled = true`, restart. Each hour the monitor builds finished weekly epochs and publishes each one that has no transaction yet (first one creates the stat cell with a Type ID, later ones update it). The type hash appears in `/v1/monitor`.

## Forwarded topology (fixed-IP VPS in front of the monitor host)

The monitor host may sit behind NAT. A VPS with a fixed IP forwards port 443 and the CKB P2P port through WireGuard. There must be **no SNAT / masquerade** on the VPS, so the monitor still sees runner source IPs (needed for geolocation and the P2P check), and replies on the monitor host must return through the tunnel.

Addresses used below: VPS public `203.0.113.10`, WireGuard `10.77.0.1` (VPS) and `10.77.0.2` (monitor host), P2P port `8115`.

### VPS: `/etc/wireguard/wg0.conf`

```ini
[Interface]
Address = 10.77.0.1/24
ListenPort = 51820
PrivateKey = <vps private key>

[Peer]
PublicKey = <monitor host public key>
# the monitor host AND every source address whose replies are routed back is covered by the
# policy routing on the other side; here only the tunnel address is needed
AllowedIPs = 10.77.0.2/32
```

### VPS: forwarding with nftables (`/etc/nftables.conf`)

```nft
table inet fwd {
  chain prerouting {
    type nat hook prerouting priority dstnat;
    # destination NAT only; do not add any masquerade/snat rule
    iifname "eth0" tcp dport { 443, 8115 } dnat ip to 10.77.0.2
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
    ct state established,related accept
    iifname "eth0" oifname "wg0" tcp dport { 443, 8115 } accept
    iifname "wg0" oifname "eth0" accept
  }
}
```

Also `sysctl -w net.ipv4.ip_forward=1`.

### Monitor host: `/etc/wireguard/wg0.conf`

```ini
[Interface]
Address = 10.77.0.2/24
PrivateKey = <monitor host private key>
# do not let wg-quick install a default route: we route selectively
Table = off
# connection marking: packets that arrived through wg0 get their replies sent back through wg0
PostUp = ip rule add fwmark 0x77 table 77 priority 100
PostUp = ip route add default via 10.77.0.1 dev wg0 table 77
PostUp = nft -f /etc/csr-network-monitor/connmark.nft
PostDown = ip rule del fwmark 0x77 table 77 priority 100
PostDown = ip route flush table 77
PostDown = nft delete table inet csrmark

[Peer]
PublicKey = <vps public key>
Endpoint = 203.0.113.10:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`AllowedIPs = 0.0.0.0/0` is safe because `Table = off` keeps it out of the main routing table; table 77 is used only for marked packets.

### Monitor host: `/etc/csr-network-monitor/connmark.nft`

```nft
table inet csrmark {
  chain pre {
    type filter hook prerouting priority mangle;
    # remember that a connection came in through the tunnel
    iifname "wg0" ct mark set 0x77
  }
  chain out {
    type route hook output priority mangle;
    # replies of such connections carry the mark and so use table 77 (back through wg0)
    ct mark 0x77 meta mark set ct mark
  }
}
```

The services (Caddy on 443, the CKB node on 8115) simply listen on all addresses; connections from the Internet arrive with the runner's real source IP and the reply goes back via `ip rule fwmark 0x77`. Set `rp_filter` to loose (`net.ipv4.conf.wg0.rp_filter=2`, `net.ipv4.conf.all.rp_filter=2`) so that packets with Internet source addresses are accepted from `wg0`.

Check: `curl https://monitor-testnet.vericell.net/v1/monitor` from outside, and look at `ss -tn` on the monitor host: peers must show real client addresses, not `10.77.0.1`.
