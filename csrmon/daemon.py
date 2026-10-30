"""The long-running service."""
import logging
import signal
import threading
import time

from . import cli, configcell, crypto, epochs, keys, scoring
from .api import Api, ApiServer
from .chain import RpcChain, TipCrossCheck
from .geo import GeoDB, load_or_create_salt
from .p2p import P2PScheduler
from .csrprobe import CsrProber
from .discovery import Discovery, parse_peers
from .config import config_warnings
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
        for w in config_warnings(c):
            log.warning("config: %s", w)
        self.secret = keys.load_or_create_secret(c.key_path)
        self.store = cli.init_db(c)
        salt = load_or_create_salt(c.salt_path)
        geo = GeoDB(c.geo_country_csv or None, c.geo_asn_csv or None, c.geo_city_csv or None)
        self.chain = RpcChain(c.node_rpc)
        second = RpcChain(c.second_tip_source) if c.second_tip_source else None
        self.cross = TipCrossCheck(self.chain, second, c.sync_threshold)
        self.prober = CsrProber(self.store, self.chain, c, self.secret, geo=geo, salt=salt)
        self.p2p = P2PScheduler(self.store, self.chain, c, paused=lambda: self.prober.paused,
                                secret=self.secret)
        self.discovery = Discovery(self.store, c)
        self.cell_writer = self.attester = None
        if c.config_type_args:
            self.cell_writer = configcell.ConfigCellWriter(self.store, self.chain, c, self.secret)
            self.attester = configcell.Attester(self.store, c, self.secret, self.cell_writer)
        self.monitor_pubkey = crypto.pubkey_from_secret(self.secret)
        self.api = Api(self.store, c, self.secret, prober=self.prober, chain=self.chain,
                       attester=self.attester, cross=self.cross)
        self.server = ApiServer(self.api, c.listen_host, c.listen_port, timeout_s=c.http_timeout_s,
                                 max_connections=c.http_max_connections)
        self.server.start()
        self.writer = (StatCellWriter(self.store, self.chain, c, self.secret)
                       if c.stat_cell_enabled else None)
        log.info("listening on %s:%s (%s)", c.listen_host, self.server.port, c.network)

    # ---- tasks ----
    def _scan_registry(self, now):
        r = configcell.scan_registry(self.store, self.chain, self.config, self.monitor_pubkey)
        if r:
            log.info("registry: %d valid, %d invalid", r["valid"], r["invalid"])

    def _clock(self, now):
        if self.cell_writer is not None and self.config.stat_cell_sighash_dep_tx:
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
        scoring.update_scores(self.store, today, self.config.provisional_days,
                              scoring.stake_required(self.config),
                              require_identity=self.config.require_identity_proof, now=now)
        self.api.invalidate()

    def _prune(self, now):
        self.store.prune(now, self.config.probe_retention_days)

    def _epochs(self, now):
        epochs.build_pending(self.store, self.chain, self.secret, self.config, now=int(now))
        if self.writer is None:
            return
        eps = self.store.epoch_states()
        for e in eps:
            if e.get("stat_cell_tx") and not e.get("published"):
                self.writer.confirm(e["epoch"])
        eps = self.store.epoch_states()
        if any(e["stat_cell_tx"] and not e["published"] for e in eps):
            return          # a transaction is in flight: each update replaces the data
        todo = [e for e in eps if not e["published"] and not e["superseded"]]
        if not todo:
            return
        newest = todo[-1]
        for e in todo[:-1]:
            self.store.set_epoch_superseded(e["epoch"])
        self.writer.publish(newest["epoch"])

    def _p2p_loop(self):
        while not self._stop.wait(5):
            try:
                for res in self.p2p.run_due():
                    if res["result"] != "ok":
                        log.info("p2p check %s: %s (%s)", res["runner_id"], res["result"],
                                 res["reason"])
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
            ["crosscheck", c.crosscheck_interval_s, self._crosscheck],
            ["aggregate", c.aggregate_interval_s, self._aggregate],
            ["prune", DAY, self._prune],
            ["epochs", HOUR, self._epochs],
            ["registry", c.probe_interval_s, self._scan_registry],
            ["clock", c.clock_update_interval_s, self._clock],
        ]
        due = {t[0]: 0 for t in tasks}
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
            p2p_thread.join(2)
            self.store.close()
        log.info("stopped")
        return 0
