"""SQLite store (thread-safe, WAL)."""
import hashlib
import json
import logging
import os
import secrets
import sqlite3
import statistics
import threading
from datetime import datetime, timedelta, timezone

from . import geo

_SCHEMA = """
create table if not exists runners(
  runner_id text primary key, service_pubkey text, peer_id text, p2p_pubkey text, reg_outpoint text,
  mode text, endpoint text, p2p_port integer, first_seen integer, last_seen integer, status text,
  flags text not null default '[]', ranking_opt_in integer, country text, region text, asn integer,
  csr_version text, ckb_version text, loc_lat integer, loc_lon integer);
create table if not exists probes(
  runner_id text, ts integer, slot integer, mode text, result text, failure_reason text,
  latency_ms integer, tip_number integer, lag integer, in_sync integer, peers_out integer,
  csr_version text, ckb_version text, ip_hash text, country text, asn integer,
  p2p_verified integer, primary key(runner_id, slot));
create index if not exists probes_ts on probes(runner_id, ts);
create table if not exists p2p_checks(
  id integer primary key autoincrement, runner_id text, ts integer, heights text, served integer,
  latency_ms integer, peer_id_seen text, result text);
create index if not exists p2p_ts on p2p_checks(runner_id, ts);
create table if not exists daily_stats(
  runner_id text, day text, probes_total integer, probes_ok integer, in_sync integer,
  p2p_total integer, p2p_ok integer, median_lag, median_peers, score real,
  primary key(runner_id, day));
create table if not exists epochs(
  epoch integer primary key, start integer, "end" integer, merkle_root text, data_hex text,
  stat_cell_tx text, summary_json text);
create table if not exists registrations(
  peer_id text, service_pubkey text, expiry_ms integer, outpoint text);
create index if not exists registrations_peer on registrations(peer_id);
create table if not exists registry_stakes(
  peer_id text, service_pubkey text, reg_outpoint text, expiry_ms integer, stake_outpoint text,
  status text, capacity_ckb integer, reason text);
create index if not exists registry_stakes_peer on registry_stakes(peer_id);
create table if not exists issued_attestations(
  id integer primary key autoincrement, peer_id text, service_pubkey text, issued_at integer,
  attestation text);
create index if not exists issued_key on issued_attestations(peer_id, service_pubkey);
create table if not exists discovery(
  ip_hash text primary key, node_id text, last_try integer, last_ok integer);
create table if not exists meta(key text primary key, value text);
"""

_STATUSES = ("active", "opted_out", "deregistered")
_PROBE_RESULTS = ("ok", "fail", "excluded")
_P2P_RESULTS = ("ok", "fail", "identity_mismatch", "error")


def day_of(ts) -> str:
    return datetime.fromtimestamp(int(ts), timezone.utc).strftime("%Y-%m-%d")


def day_start(day) -> int:
    d = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    return int(d.timestamp())


def add_days(day, n) -> str:
    d = datetime.strptime(day, "%Y-%m-%d") + timedelta(days=n)
    return d.strftime("%Y-%m-%d")


def _whole(x):
    if x is None:
        return None
    return int(x) if float(x) == int(x) else x


log = logging.getLogger("csrmon")


def _private_file(path):
    """Create the database file with mode 0600, or tighten an existing one."""
    if path == ":memory:" or str(path).startswith("file:"):
        return
    if not os.path.exists(path):
        os.close(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600))
    elif os.stat(path).st_mode & 0o077:
        os.chmod(path, 0o600)
        log.info("database file %s was readable by others; mode set to 0600", path)


class Store:
    def __init__(self, path):
        self._lock = threading.RLock()
        _private_file(path)
        self._con = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._con.row_factory = sqlite3.Row
        with self._lock:
            self._con.execute("pragma journal_mode=wal")
            self._con.execute("pragma busy_timeout=5000")
            dcols = {r[1] for r in self._con.execute("pragma table_info(discovery)")}
            if dcols and "ip_hash" not in dcols:
                # old rows hold plain IPs; the table is only a back-off cache
                self._con.execute("drop table discovery")
            self._con.executescript(_SCHEMA)
            cols = {r[1] for r in self._con.execute("pragma table_info(probes)")}
            if "p2p_verified" not in cols:
                self._con.execute("ALTER TABLE probes ADD COLUMN p2p_verified INTEGER")
            rcols = {r[1] for r in self._con.execute("pragma table_info(runners)")}
            for col in ("loc_lat", "loc_lon"):
                if col not in rcols:
                    self._con.execute(f"ALTER TABLE runners ADD COLUMN {col} INTEGER")

    def close(self):
        with self._lock:
            self._con.close()

    def _all(self, sql, args=()):
        with self._lock:
            return [dict(r) for r in self._con.execute(sql, args).fetchall()]

    def _one(self, sql, args=()):
        rows = self._all(sql, args)
        return rows[0] if rows else None

    # ---- runners ----
    @staticmethod
    def _runner(r):
        if r is None:
            return None
        r["flags"] = sorted(json.loads(r["flags"] or "[]"))
        r["ranking_opt_in"] = bool(r["ranking_opt_in"])
        return r

    def upsert_runner(self, runner_id, *, service_pubkey, peer_id, p2p_pubkey, reg_outpoint, mode,
                      endpoint, p2p_port, ranking_opt_in, now) -> bool:
        status = "active" if ranking_opt_in else "opted_out"
        opt = 1 if ranking_opt_in else 0
        with self._lock:
            exists = self._con.execute("select 1 from runners where runner_id=?",
                                       (runner_id,)).fetchone()
            if exists:
                self._con.execute(
                    "update runners set service_pubkey=?, peer_id=?, p2p_pubkey=?, reg_outpoint=?,"
                    " mode=?, endpoint=?, p2p_port=?, ranking_opt_in=?, status=? where runner_id=?",
                    (service_pubkey, peer_id, p2p_pubkey, reg_outpoint, mode, endpoint, p2p_port,
                     opt, status, runner_id))
                return False
            self._con.execute(
                "insert into runners(runner_id, service_pubkey, peer_id, p2p_pubkey, reg_outpoint,"
                " mode, endpoint, p2p_port, first_seen, last_seen, status, flags, ranking_opt_in)"
                " values(?,?,?,?,?,?,?,?,?,NULL,?,'[]',?)",
                (runner_id, service_pubkey, peer_id, p2p_pubkey, reg_outpoint, mode, endpoint,
                 p2p_port, now, status, opt))
            return True

    def get_runner(self, runner_id):
        return self._runner(self._one("select * from runners where runner_id=?", (runner_id,)))

    def list_runners(self, statuses=("active",)):
        if statuses is None:
            rows = self._all("select * from runners order by runner_id")
        else:
            statuses = tuple(statuses)
            q = ",".join("?" * len(statuses))
            rows = self._all(f"select * from runners where status in ({q}) order by runner_id",
                             statuses)
        return [self._runner(r) for r in rows]

    def set_status(self, runner_id, status):
        if status not in _STATUSES:
            raise ValueError(f"invalid status {status!r}")
        with self._lock:
            self._con.execute("update runners set status=? where runner_id=?", (status, runner_id))

    def set_flag(self, runner_id, flag, on):
        with self._lock:
            row = self._con.execute("select flags from runners where runner_id=?",
                                    (runner_id,)).fetchone()
            if row is None:
                return
            flags = set(json.loads(row[0] or "[]"))
            flags.add(flag) if on else flags.discard(flag)
            self._con.execute("update runners set flags=? where runner_id=?",
                              (json.dumps(sorted(flags)), runner_id))

    def find_runner_by_peer(self, peer_id):
        return self._runner(self._one(
            "select * from runners where peer_id=? and status='active'"
            " order by last_seen is null, last_seen desc, first_seen desc limit 1", (peer_id,)))

    # ---- registrations / attestations / discovery ----
    def set_registrations(self, rows):
        with self._lock:
            self._con.execute("begin")
            try:
                self._con.execute("delete from registrations")
                self._con.executemany(
                    "insert into registrations(peer_id, service_pubkey, expiry_ms, outpoint)"
                    " values(?,?,?,?)",
                    [(r["peer_id"], r["service_pubkey"], r["expiry_ms"], r["outpoint"])
                     for r in rows])
                self._con.execute("commit")
            except Exception:
                self._con.execute("rollback")
                raise

    def registration_for(self, peer_id):
        return self._one(
            "select peer_id, service_pubkey, expiry_ms, outpoint from registrations"
            " where peer_id=? order by expiry_ms desc limit 1", (peer_id,))

    _STAKE_KEYS = ("peer_id", "service_pubkey", "reg_outpoint", "expiry_ms", "stake_outpoint",
                   "status", "capacity_ckb", "reason")

    def set_stakes(self, rows):
        with self._lock:
            self._con.execute("begin")
            try:
                self._con.execute("delete from registry_stakes")
                self._con.executemany(
                    f"insert into registry_stakes({', '.join(self._STAKE_KEYS)}) values(?,?,?,?,?,?,?,?)",
                    [tuple(r[k] for k in self._STAKE_KEYS) for r in rows])
                self._con.execute("commit")
            except Exception:
                self._con.execute("rollback")
                raise

    def stake_for(self, peer_id):
        return self._one(
            f"select {', '.join(self._STAKE_KEYS)} from registry_stakes where peer_id=?"
            " order by status='deposited' desc, expiry_ms desc, reg_outpoint asc limit 1", (peer_id,))

    def stake_user(self, stake_outpoint):
        r = self._one("select peer_id from registry_stakes where stake_outpoint=?"
                      " and status='deposited' limit 1", (stake_outpoint,))
        return r["peer_id"] if r else None

    def save_issued(self, peer_id, service_pubkey, *, issued_at, attestation):
        with self._lock:
            self._con.execute(
                "insert into issued_attestations(peer_id, service_pubkey, issued_at, attestation)"
                " values(?,?,?,?)",
                (peer_id, service_pubkey, issued_at, json.dumps(attestation, sort_keys=True)))

    def last_issued(self, peer_id, service_pubkey):
        r = self._one(
            "select issued_at, attestation from issued_attestations where peer_id=? and"
            " service_pubkey=? order by issued_at desc, id desc limit 1", (peer_id, service_pubkey))
        if r is None:
            return None
        return {"issued_at": r["issued_at"], "attestation": json.loads(r["attestation"])}

    def _discovery_key(self, ip):
        with self._lock:
            salt = self.get_meta("discovery_salt")
            if salt is None:
                salt = secrets.token_hex(32)
                self.set_meta("discovery_salt", salt)
        return hashlib.sha256(bytes.fromhex(salt) + str(ip).encode()).hexdigest()

    def discovery_mark(self, ip, node_id, *, ts, ok):
        key = self._discovery_key(ip)
        with self._lock:
            self._con.execute(
                "insert into discovery(ip_hash, node_id, last_try, last_ok) values(?,?,?,?)"
                " on conflict(ip_hash) do update set node_id=excluded.node_id,"
                " last_try=excluded.last_try, last_ok=coalesce(excluded.last_ok, last_ok)",
                (key, node_id, ts, ts if ok else None))

    def discovery_get(self, ip):
        return self._one("select ip_hash, node_id, last_try, last_ok from discovery"
                         " where ip_hash=?", (self._discovery_key(ip),))

    # ---- probes ----
    def record_probe(self, runner_id, *, ts, slot, mode, result, failure_reason=None,
                     latency_ms=None, tip_number=None, lag=None, in_sync=None, peers_out=None,
                     csr_version=None, ckb_version=None, ip_hash=None, country=None,
                     asn=None, p2p_verified=None, loc_lat=None, loc_lon=None) -> bool:
        if result not in _PROBE_RESULTS:
            raise ValueError(f"invalid probe result {result!r}")
        ins = None if in_sync is None else (1 if in_sync else 0)
        pv = None if p2p_verified is None else (1 if p2p_verified else 0)
        with self._lock:
            cur = self._con.execute(
                "insert or ignore into probes(runner_id, ts, slot, mode, result, failure_reason,"
                " latency_ms, tip_number, lag, in_sync, peers_out, csr_version, ckb_version,"
                " ip_hash, country, asn, p2p_verified) values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (runner_id, ts, slot, mode, result, failure_reason, latency_ms, tip_number, lag,
                 ins, peers_out, csr_version, ckb_version, ip_hash, country, asn, pv))
            if cur.rowcount == 0:
                return False
            if result == "ok":
                self._con.execute(
                    "update runners set last_seen=max(coalesce(last_seen,0), ?) where runner_id=?",
                    (ts, runner_id))
            if country is not None:
                lat, lon = (loc_lat, loc_lon)
                if country == "??" or lat is None or lon is None:
                    lat = lon = None
                self._con.execute(
                    "update runners set country=?, region=?, asn=?, loc_lat=?, loc_lon=?"
                    " where runner_id=?",
                    (country, geo.region_for(country), asn, lat, lon, runner_id))
            if csr_version is not None:
                self._con.execute(
                    "update runners set csr_version=?, ckb_version=? where runner_id=?",
                    (csr_version, ckb_version, runner_id))
            return True

    @staticmethod
    def _probe(r):
        if r is not None:
            for k in ("in_sync", "p2p_verified"):
                if r[k] is not None:
                    r[k] = bool(r[k])
        return r

    def probes(self, runner_id, since=None, until=None):
        sql, args = "select * from probes where runner_id=?", [runner_id]
        if since is not None:
            sql += " and ts>=?"
            args.append(since)
        if until is not None:
            sql += " and ts<?"
            args.append(until)
        return [self._probe(r) for r in self._all(sql + " order by ts, slot", args)]

    def last_probe(self, runner_id):
        return self._probe(self._one(
            "select * from probes where runner_id=? order by ts desc, slot desc limit 1",
            (runner_id,)))

    def has_probe(self, runner_id, slot) -> bool:
        return self._one("select 1 as x from probes where runner_id=? and slot=?",
                         (runner_id, slot)) is not None

    # ---- p2p ----
    def record_p2p_check(self, runner_id, *, ts, heights, served, latency_ms, peer_id_seen, result):
        if result not in _P2P_RESULTS:
            raise ValueError(f"invalid p2p result {result!r}")
        with self._lock:
            self._con.execute(
                "insert into p2p_checks(runner_id, ts, heights, served, latency_ms, peer_id_seen,"
                " result) values(?,?,?,?,?,?,?)",
                (runner_id, ts, json.dumps(list(heights)), served, latency_ms, peer_id_seen,
                 result))

    @staticmethod
    def _p2p(r):
        if r is not None:
            r.pop("id", None)
            r["heights"] = json.loads(r["heights"])
        return r

    def p2p_checks(self, runner_id):
        return [self._p2p(r) for r in self._all(
            "select * from p2p_checks where runner_id=? order by ts, id", (runner_id,))]

    def last_p2p_check(self, runner_id):
        return self._p2p(self._one(
            "select * from p2p_checks where runner_id=? order by ts desc, id desc limit 1",
            (runner_id,)))

    # ---- daily ----
    def aggregate_day(self, day) -> int:
        lo, hi = day_start(day), day_start(day) + 86400
        with self._lock:
            ids = {r[0] for r in self._con.execute(
                "select runner_id from probes where ts>=? and ts<? union "
                "select runner_id from p2p_checks where ts>=? and ts<?", (lo, hi, lo, hi))}
            for rid in sorted(ids):
                pr = self._all("select result, in_sync, lag, peers_out from probes"
                               " where runner_id=? and ts>=? and ts<?", (rid, lo, hi))
                ok = [p for p in pr if p["result"] == "ok"]
                total = len(ok) + sum(1 for p in pr if p["result"] == "fail")
                lags = [p["lag"] for p in ok if p["lag"] is not None]
                peers = [p["peers_out"] for p in ok if p["peers_out"] is not None]
                p2 = self._all("select result from p2p_checks where runner_id=? and ts>=? and ts<?",
                               (rid, lo, hi))
                vals = (total, len(ok), sum(1 for p in ok if p["in_sync"]), len(p2),
                        sum(1 for c in p2 if c["result"] == "ok"),
                        statistics.median(lags) if lags else None,
                        statistics.median(peers) if peers else None)
                self._con.execute(
                    "insert into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                    " p2p_total, p2p_ok, median_lag, median_peers) values(?,?,?,?,?,?,?,?,?)"
                    " on conflict(runner_id, day) do update set probes_total=excluded.probes_total,"
                    " probes_ok=excluded.probes_ok, in_sync=excluded.in_sync,"
                    " p2p_total=excluded.p2p_total, p2p_ok=excluded.p2p_ok,"
                    " median_lag=excluded.median_lag, median_peers=excluded.median_peers",
                    (rid, day) + vals)
            return len(ids)

    def daily_stats(self, runner_id, from_day, to_day):
        rows = self._all("select * from daily_stats where runner_id=? and day>=? and day<=?"
                         " order by day", (runner_id, from_day, to_day))
        for r in rows:
            r["median_lag"] = _whole(r["median_lag"])
            r["median_peers"] = _whole(r["median_peers"])
        return rows

    def set_daily_score(self, runner_id, day, score):
        with self._lock:
            self._con.execute(
                "insert into daily_stats(runner_id, day, probes_total, probes_ok, in_sync,"
                " p2p_total, p2p_ok, score) values(?,?,0,0,0,0,0,?)"
                " on conflict(runner_id, day) do update set score=excluded.score",
                (runner_id, day, score))

    def prune(self, now, keep_days) -> int:
        cutoff = now - keep_days * 86400
        with self._lock:
            n = self._con.execute("delete from probes where ts<?", (cutoff,)).rowcount
            n += self._con.execute("delete from p2p_checks where ts<?", (cutoff,)).rowcount
            return n

    # ---- meta / epochs ----
    def get_meta(self, key, default=None):
        r = self._one("select value from meta where key=?", (key,))
        return default if r is None else r["value"]

    def set_meta(self, key, value):
        with self._lock:
            self._con.execute("insert or replace into meta(key, value) values(?,?)",
                              (key, str(value)))

    def save_epoch(self, epoch, *, start, end, merkle_root, data_hex, summary):
        with self._lock:
            self._con.execute(
                'insert into epochs(epoch, start, "end", merkle_root, data_hex, summary_json)'
                ' values(?,?,?,?,?,?) on conflict(epoch) do update set start=excluded.start,'
                ' "end"=excluded."end", merkle_root=excluded.merkle_root,'
                ' data_hex=excluded.data_hex, summary_json=excluded.summary_json',
                (epoch, start, end, merkle_root, data_hex,
                 json.dumps(summary, sort_keys=True)))

    def set_epoch_tx(self, epoch, tx_hash):
        with self._lock:
            self._con.execute("update epochs set stat_cell_tx=? where epoch=?", (tx_hash, epoch))

    @staticmethod
    def _epoch(r):
        if r is None:
            return None
        return {"epoch": r["epoch"], "start": r["start"], "end": r["end"],
                "merkle_root": r["merkle_root"], "data_hex": r["data_hex"],
                "stat_cell_tx": r["stat_cell_tx"], "summary": json.loads(r["summary_json"])}

    def get_epoch(self, epoch):
        return self._epoch(self._one("select * from epochs where epoch=?", (epoch,)))

    def list_epochs(self):
        return [self._epoch(r) for r in self._all("select * from epochs order by epoch")]
