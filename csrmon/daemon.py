"""The long-running service."""
import logging
import signal
import threading
import time

from . import cli, configcell, crypto, epochs, keys, registry, scoring
from .api import Api, ApiServer
from .chain import RpcChain, TipCrossCheck
from .geo import GeoDB, load_or_create_salt
from .p2p import P2PChecker, P2PScheduler
from .csrprobe import CsrProber
from .discovery import Discovery, parse_peers
from .stat_cell import StatCellWriter
from .store import add_days, day_of

log = logging.getLogger("csrmon")

HOUR = 3600
DAY = 86400


class Daemon:
    def __init__(self, config):
        self.config = config
        self._stop = threading.Event()
        self.server = None
        self.store = None

    def stop(self, *_):
        self._stop.set()

    def _setup(self):
        c = self.config
        self.secret = keys.load_or_create_secret(c.key_path)
        self.store = cli.init_db(c)
        salt = load_or_create_salt(c.salt_path)
        geo = GeoDB(c.geo_country_csv or None, c.geo_asn_csv or None, c.geo_city_csv or None)
        self.chain = RpcChain(c.node_rpc)
        second = RpcChain(c.second_tip_source) if c.second_tip_source else None
        self.cross = TipCrossCheck(self.chain, second, c.sync_threshold)
        self.prober = CsrProber(self.store, self.chain, c, self.secret, geo=geo, salt=salt)
        self.p2p = None
        if c.p2p_check_cmd:
            checker = P2PChecker(c.p2p_check_cmd, c.p2p_check_timeout_s, c.network)
            self.p2p = P2PScheduler(self.store, self.chain, checker, c)
        self.discovery = Discovery(self.store, c)
        self.cell_writer = self.attester = None
        if c.config_type_args and not c.config_type_code_hash:
            log.warning("config_type_args is set but config_type_code_hash is not: config cell,"
                        " registry scan and attestations are disabled")
        if configcell.configured(c):
            self.cell_writer = configcell.ConfigCellWriter(self.store, self.chain, c, self.secret)
            self.attester = configcell.Attester(self.store, c, self.secret, self.cell_writer)
        self.monitor_pubkey = crypto.pubkey_from_secret(self.secret)
        self.api = Api(self.store, c, self.secret, prober=self.prober, chain=self.chain,
                       attester=self.attester)
        self.server = ApiServer(self.api, c.listen_host, c.listen_port)
        self.server.start()
        self.writer = (StatCellWriter(self.store, self.chain, c, self.secret)
                       if c.stat_cell_enabled else None)
        log.info("listening on %s:%s (%s)", c.listen_host, self.server.port, c.network)

    # ---- tasks ----
    def _sync(self, now):
        r = registry.sync_registrations(self.store, self.chain, self.config, now)
        if r["added"] or r["removed"] or r["updated"]:
            log.info("registrations: +%d ~%d -%d", len(r["added"]), len(r["updated"]),
                     len(r["removed"]))

    def _scan_registry(self, now):
        r = configcell.scan_registry(self.store, self.chain, self.config, self.monitor_pubkey)
        if r:
            log.info("registry: %d valid, %d invalid", r["valid"], r["invalid"])

    def _clock(self, now):
        if (self.cell_writer is not None and self.config.stat_cell_sighash_dep_tx
                and self.config.config_type_dep_tx):
            self.cell_writer.update_clock()

    def _discovery_loop(self):
        while not self._stop.is_set():
            try:
                now = time.time()
                peers = parse_peers(self.chain.get_peers())
                self.prober.set_peers(peers)
                for res in self.prober.discover(self.discovery.due(peers, now), now):
                    if res.get("result") == "ok":
                        log.info("discovered CSR node %s at %s", res["node_id"], res["endpoint"])
                for res in self.prober.discover(self.discovery.registered(now), now):
                    if res.get("result") == "ok":
                        log.info("registered CSR node %s answers at its endpoint", res["node_id"])
            except Exception:
                log.exception("discovery failed")
            self._stop.wait(self.config.discovery_interval_s)

    def _crosscheck(self, now):
        paused = not self.cross.check()
        if paused != self.prober.paused:
            log.warning("probing %s (tip cross-check %s)", "paused" if paused else "resumed",
                        "failed" if paused else "ok")
        self.prober.paused = paused

    def _aggregate(self, now):
        today = day_of(now)
        self.store.aggregate_day(today)
        self.store.aggregate_day(add_days(today, -1))
        scoring.update_scores(self.store, today, self.config.provisional_days)
        self.api.invalidate()

    def _prune(self, now):
        self.store.prune(now, self.config.probe_retention_days)

    def _epochs(self, now):
        epochs.build_pending(self.store, self.chain, self.secret, self.config, now=int(now))
        if self.writer is None:
            return
        for e in self.store.list_epochs():
            if not e.get("stat_cell_tx"):
                self.writer.publish(e["epoch"])

    def _p2p_loop(self):
        while not self._stop.wait(5):
            try:
                self.p2p.run_due()
            except Exception:
                log.exception("p2p task failed")

    def run(self) -> int:
        logging.basicConfig(level=logging.INFO, stream=None,
                            format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        try:
            signal.signal(signal.SIGTERM, self.stop)
            signal.signal(signal.SIGINT, self.stop)
        except ValueError:      # not in the main thread
            pass
        self._setup()
        c = self.config
        tasks = [  # name, period, function; next run time starts at 0 = immediately
            ["sync", c.probe_interval_s, self._sync],
            ["crosscheck", c.crosscheck_interval_s, self._crosscheck],
            ["aggregate", c.aggregate_interval_s, self._aggregate],
            ["prune", DAY, self._prune],
            ["epochs", HOUR, self._epochs],
            ["registry", c.probe_interval_s, self._scan_registry],
            ["clock", c.clock_update_interval_s, self._clock],
        ]
        due = {t[0]: 0 for t in tasks}
        p2p_thread = None
        if self.p2p is not None:
            p2p_thread = threading.Thread(target=self._p2p_loop, daemon=True)
            p2p_thread.start()
        disc_thread = threading.Thread(target=self._discovery_loop, daemon=True)
        disc_thread.start()
        try:
            while not self._stop.is_set():
                now = time.time()
                for name, period, fn in tasks:
                    if now >= due[name]:
                        due[name] = now + period
                        try:
                            fn(now)
                        except Exception:
                            log.exception("task %s failed", name)
                try:
                    self.prober.run_due()
                except Exception:
                    log.exception("task probe failed")
                self._stop.wait(0.5)
        finally:
            self._stop.set()
            try:
                self.server.stop()
            except Exception:
                log.exception("server stop failed")
            disc_thread.join(2)
            if p2p_thread is not None:
                p2p_thread.join(2)
            self.store.close()
        log.info("stopped")
        return 0
