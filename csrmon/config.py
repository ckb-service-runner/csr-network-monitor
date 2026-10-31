"""TOML configuration."""
import tomllib
from dataclasses import dataclass, field, fields
from urllib.parse import urlparse


class ConfigError(Exception):
    pass


A7_REGISTRY_HASH = "0x47fee83ea91eabdfc8827045f63fe051b8fee5c05b9280a35f42f2e3597d3f36"


@dataclass
class Config:
    network: str
    public_url: str
    db_path: str
    key_path: str
    node_rpc: str = "http://127.0.0.1:8114"
    listen_host: str = "127.0.0.1"
    listen_port: int = 8480
    salt_path: str = ""
    probe_interval_s: int = 600
    probe_jitter_s: int = 60
    probe_timeout_s: float = 5
    probe_workers: int = 32
    sync_threshold: int = 10
    second_tip_source: str = ""
    crosscheck_interval_s: int = 600
    aggregate_interval_s: int = 600
    allow_insecure_endpoints: bool = False
    geo_country_csv: str = ""
    geo_asn_csv: str = ""
    geo_city_csv: str = ""
    p2p_interval_s: int = 86400
    p2p_public_address: str = ""
    require_identity_proof: bool = False
    rate_limit_per_min: int = 60
    rate_limit_post_per_min: int = 20
    http_timeout_s: int = 10
    http_max_connections: int = 64
    trusted_proxies: list = field(default_factory=lambda: ["127.0.0.1", "::1"])
    min_stake_ckb: int = 10000
    require_checkin_sig: bool = False
    gate_min_days: int = 120
    gate_min_runners: int = 20
    gate_max_asn_share: float = 0.25
    gate_max_country_share: float = 0.5
    provisional_days: int = 7
    probe_retention_days: int = 90
    stat_cell_enabled: bool = False
    stat_cell_capacity_ckb: int = 400
    stat_cell_fee_shannons: int = 100000
    stat_cell_acp_code_hash: str = ""
    stat_cell_acp_hash_type: str = "type"
    stat_cell_acp_dep_tx: str = ""
    stat_cell_acp_dep_index: int = 0
    stat_cell_acp_dep_type: str = "dep_group"
    stat_cell_sighash_code_hash: str = (
        "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8")
    stat_cell_sighash_hash_type: str = "type"
    stat_cell_sighash_dep_tx: str = ""
    stat_cell_sighash_dep_index: int = 0
    ping_port: int = 8131
    discovery_interval_s: int = 600
    discovery_backoff_s: int = 86400
    answer_deadline_s: int = 60
    reachable_window_s: int = 3600
    csr_registry_code_hash: str = ""
    csr_registry_hash_type: str = "data2"
    config_type_args: str = ""
    config_type_code_hash: str = ""
    config_type_hash_type: str = "data2"
    config_type_dep_tx: str = ""
    config_type_dep_index: int = 0
    clock_update_interval_s: int = 3600
    clock_update_fee_shannons: int = 100000
    attest_validity_days: int = 7
    attest_min_ok_24h: int = 1
    attest_cache_s: int = 3600
    attest_max_clock_age_s: int = 10800


_REQUIRED = {"network", "public_url", "db_path", "key_path"}
_NONEMPTY = _REQUIRED
# minimum allowed value (inclusive) for numeric keys
_MIN = {
    "listen_port": 0, "probe_interval_s": 1, "probe_jitter_s": 0,
    "probe_workers": 1, "sync_threshold": 0, "crosscheck_interval_s": 1,
    "aggregate_interval_s": 1, "p2p_interval_s": 1,
    "rate_limit_per_min": 1, "rate_limit_post_per_min": 1, "http_timeout_s": 1,
    "http_max_connections": 1, "gate_min_days": 1, "gate_min_runners": 1,
    "provisional_days": 0, "probe_retention_days": 1,
    "ping_port": 1, "discovery_interval_s": 1, "discovery_backoff_s": 1,
    "answer_deadline_s": 1, "reachable_window_s": 1, "clock_update_interval_s": 1,
    "attest_validity_days": 1, "attest_min_ok_24h": 1, "attest_cache_s": 1,
    "min_stake_ckb": 1, "attest_max_clock_age_s": 600, "config_type_dep_index": 0,
}
# maximum allowed value (inclusive); the on-chain cap is 8 days beyond the clock (D24 A)
_MAX = {"attest_validity_days": 7, "config_type_dep_index": 0xFFFFFFFF}
_HASH_TYPES = ("type", "data", "data1", "data2")
# keys that existed once and were removed; a config that still has them gets a clear message
_REMOVED = {
    "p2p_check_cmd": "the external P2P helper was removed; the monitor now checks runners through"
                     " its own node (set p2p_public_address, see docs/INSTALL.md)",
    "p2p_check_timeout_s": "the external P2P helper was removed; delete this key",
}


def _check_type(name, value, default):
    if isinstance(default, bool):
        ok = isinstance(value, bool)
    elif name == "probe_timeout_s":
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    elif isinstance(default, float):
        ok = isinstance(value, (int, float)) and not isinstance(value, bool)
    elif isinstance(default, int):
        ok = isinstance(value, int) and not isinstance(value, bool)
    elif isinstance(default, str):
        ok = isinstance(value, str)
    elif isinstance(default, list):
        ok = isinstance(value, list) and all(isinstance(v, str) for v in value)
    else:
        ok = True
    if not ok:
        raise ConfigError(f"wrong type for {name!r}")


_REMOVED_KEYS = ("registration_code_hash", "registration_hash_type", "registration_args")


def load_config(path) -> Config:
    try:
        with open(path, "rb") as f:
            raw = tomllib.load(f)
    except OSError as e:
        raise ConfigError(f"cannot read config {path}: {e}") from e
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"invalid TOML in {path}: {e}") from e

    old = [k for k in _REMOVED_KEYS if k in raw]
    if old:
        raise ConfigError(f"config keys {', '.join(old)} are no longer supported (the old "
                          "registration scan was removed); delete them from the config")
    known = {f.name: f for f in fields(Config)}
    for k in raw:
        if k in _REMOVED:
            raise ConfigError(f"config key {k!r} is no longer supported: {_REMOVED[k]}")
        if k not in known:
            raise ConfigError(f"unknown config key {k!r}")
    for k in _REQUIRED:
        if k not in raw:
            raise ConfigError(f"missing required key {k!r}")

    defaults = Config("", "", "", "")
    for k, v in raw.items():
        _check_type(k, v, getattr(defaults, k))
        if k in _NONEMPTY and not v:
            raise ConfigError(f"{k!r} must not be empty")
        if k in _MIN and v < _MIN[k]:
            raise ConfigError(f"{k!r} must be >= {_MIN[k]}")
        if k in _MAX and v > _MAX[k]:
            raise ConfigError(f"{k!r} must be <= {_MAX[k]}")
    if "probe_timeout_s" in raw and raw["probe_timeout_s"] <= 0:
        raise ConfigError("'probe_timeout_s' must be > 0")
    for k in ("listen_port", "ping_port"):
        if k in raw and raw[k] > 65535:
            raise ConfigError(f"{k!r} must be <= 65535")

    cfg = Config(**raw)
    if cfg.network not in ("testnet", "mainnet"):
        raise ConfigError("'network' must be 'testnet' or 'mainnet'")
    for k in ("stat_cell_acp_hash_type",
              "stat_cell_sighash_hash_type", "csr_registry_hash_type",
              "config_type_hash_type"):
        if getattr(cfg, k) not in _HASH_TYPES:
            raise ConfigError(f"{k!r} must be one of {_HASH_TYPES}")
    if cfg.stat_cell_acp_dep_type not in ("code", "dep_group"):
        raise ConfigError("'stat_cell_acp_dep_type' must be 'code' or 'dep_group'")
    for k in ("gate_max_asn_share", "gate_max_country_share"):
        if not 0 <= getattr(cfg, k) <= 1:
            raise ConfigError(f"{k!r} must be between 0 and 1")

    if cfg.p2p_public_address:
        a = cfg.p2p_public_address
        parts = a.split("/")
        if (not a.startswith("/") or "/p2p/" not in a or not parts[-1]
                or parts[-2] != "p2p" or any(c.isspace() for c in a)):
            raise ConfigError("'p2p_public_address' must be a multiaddr ending in /p2p/<node id>")

    for k in ("config_type_args", "config_type_code_hash", "config_type_dep_tx"):
        a = getattr(cfg, k)
        if a and not (a.startswith("0x") and len(a) == 66
                      and all(c in "0123456789abcdefABCDEF" for c in a[2:])):
            raise ConfigError(f"{k!r} must be empty or 32 bytes hex (0x...)")

    try:
        u = urlparse(cfg.node_rpc)
        host = u.hostname
    except ValueError as e:
        raise ConfigError("invalid 'node_rpc'") from e
    if u.scheme != "http" or host not in ("127.0.0.1", "localhost", "::1"):
        raise ConfigError("'node_rpc' must be an http:// URL on 127.0.0.1, localhost or ::1")

    if cfg.stat_cell_enabled:
        for k in ("stat_cell_acp_code_hash", "stat_cell_acp_dep_tx",
                  "stat_cell_sighash_dep_tx"):
            if not getattr(cfg, k):
                raise ConfigError(f"{k!r} is required when stat_cell_enabled")

    if not cfg.salt_path:
        cfg.salt_path = cfg.db_path + ".salt"
    return cfg


def config_warnings(config) -> list:
    """Sentences about settings that silently disable or weaken a duty of the monitor."""
    out = []
    if not config.csr_registry_code_hash or not config.config_type_args:
        out.append("no registry scan: csr_registry_code_hash and config_type_args must both be"
                   " set, otherwise registrations, stakes and attestations are not available.")
    if config.csr_registry_code_hash.lower() == A7_REGISTRY_HASH:
        out.append("csr_registry_code_hash is the old A7 registry; the current A8 registry hash"
                   " is in the runner repository (deployments/testnet.json).")
    if not config.second_tip_source:
        out.append("second_tip_source is empty: the tip cross-check has no independent source"
                   " and cannot detect a local node that is stuck on a wrong chain.")
    return out
