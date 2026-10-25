"""Command line."""
import argparse
import json
import os
import sys
import time

from . import crypto, keys
from .config import ConfigError, config_warnings, load_config
from .hashing import blake160, to_hex


def _parser():
    p = argparse.ArgumentParser(prog="csrmon", description="CSR Network Monitor")
    sub = p.add_subparsers(dest="command", required=True)
    for name, text in (("check-config", "validate the configuration"),
                       ("keygen", "load or create the monitor key"),
                       ("show-key", "show the monitor public key"),
                       ("init-db", "create the database"),
                       ("run", "run the monitor service")):
        s = sub.add_parser(name, help=text)
        s.add_argument("--config", required=True, metavar="PATH")
    return p


def _key_info(secret):
    pk = crypto.pubkey_from_secret(secret)
    return json.dumps({"pubkey": to_hex(pk), "blake160": to_hex(blake160(pk))})


def init_db(config):
    from .store import Store
    d = os.path.dirname(os.path.abspath(config.db_path))
    os.makedirs(d, exist_ok=True)
    store = Store(config.db_path)
    if store.get_meta("monitor_start") is None:
        store.set_meta("monitor_start", int(time.time()))
    return store


def main(argv=None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) and e.code else 2
    try:
        config = load_config(args.config)
    except ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    cmd = args.command
    try:
        if cmd == "check-config":
            for w in config_warnings(config):
                print(f"warning: {w}", file=sys.stderr)
            if config.stat_cell_enabled and (not config.csr_registry_code_hash
                                             or not config.config_type_args):
                print("config error: stat_cell_enabled needs csr_registry_code_hash and"
                      " config_type_args", file=sys.stderr)
                return 2
            print("ok")
        elif cmd == "keygen":
            print(_key_info(keys.load_or_create_secret(config.key_path)))
        elif cmd == "show-key":
            if not os.path.exists(config.key_path):
                print(f"no key file at {config.key_path}; run keygen", file=sys.stderr)
                return 1
            print(_key_info(keys.load_or_create_secret(config.key_path)))
        elif cmd == "init-db":
            init_db(config).close()
            print("ok")
        elif cmd == "run":
            from .daemon import Daemon
            return Daemon(config).run()
    except keys.KeyFileError as e:
        print(f"key error: {e}", file=sys.stderr)
        return 1
    return 0
