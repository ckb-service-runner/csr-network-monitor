"""Offline country/ASN lookup, region table, IP hashing and the salt file."""
import bisect
import csv
import ipaddress
import os
import secrets
from array import array

from .hashing import ckb_blake2b, from_hex, to_hex

_REGIONS = {
    "AF": "DZ AO BJ BW BF BI CV CM CF TD KM CG CD CI DJ EG GQ ER SZ ET GA GM GH GN GW KE LS LR LY "
          "MG MW ML MR MU YT MA MZ NA NE NG RE RW SH ST SN SC SL SO ZA SS SD TZ TG TN UG EH ZM ZW",
    "AN": "AQ BV GS HM TF",
    "AS": "AF AM AZ BH BD BT BN KH CN CY GE HK IN ID IR IQ IL JP JO KZ KW KG LA LB MO MY MV MN MM "
          "NP KP OM PK PS PH QA SA SG KR LK SY TW TJ TH TL TR TM AE UZ VN YE IO CX CC",
    "EU": "AX AL AD AT BY BE BA BG HR CZ DK EE FO FI FR DE GI GR GG VA HU IS IE IM IT JE LV LI LT "
          "LU MT MD MC ME NL MK NO PL PT RO RU SM RS SK SI ES SJ SE CH UA GB",
    "NA": "AI AG AW BS BB BZ BM BQ VG CA KY CR CU CW DM DO SV GL GD GP GT HT HN JM MQ MX MS NI PA "
          "PR BL KN LC MF PM VC SX TT TC US VI UM",
    "OC": "AS AU CK FJ PF GU KI MH FM NR NC NZ NU NF MP PW PG PN WS SB TK TO TV VU WF",
    "SA": "AR BO BR CL CO EC FK GF GY PY PE SR UY VE",
}
COUNTRY_REGION = {cc: reg for reg, codes in _REGIONS.items() for cc in codes.split()}


def region_for(cc) -> str:
    if not cc:
        return "??"
    return COUNTRY_REGION.get(str(cc).upper(), "??")


class _Ranges:
    """Sorted, non-overlapping-lookup ranges for one IP family."""

    def __init__(self, wide):
        self.starts = [] if wide else array("I")
        self.ends = [] if wide else array("I")
        self.vals = array("I")

    def freeze(self, rows):
        rows.sort(key=lambda r: r[0])
        for s, e, v in rows:
            self.starts.append(s)
            self.ends.append(e)
            self.vals.append(v)

    def find(self, n):
        i = bisect.bisect_right(self.starts, n) - 1
        if i >= 0 and n <= self.ends[i]:
            return self.vals[i]
        return None


class _Table:
    def __init__(self, path):
        self.values = [None]   # index 0 unused
        self._index = {}
        self.v4 = _Ranges(False)
        self.v6 = _Ranges(True)
        if not path:
            return
        r4, r6 = [], []
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) < 3:
                    continue
                try:
                    a = ipaddress.ip_address(row[0].strip())
                    b = ipaddress.ip_address(row[1].strip())
                except ValueError:
                    continue
                val = self._intern(self._value(row))
                (r4 if a.version == 4 else r6).append((int(a), int(b), val))
        self.v4.freeze(r4)
        self.v6.freeze(r6)

    @staticmethod
    def _value(row):
        return tuple(c.strip() for c in row[2:4])

    def _intern(self, v):
        i = self._index.get(v)
        if i is None:
            i = len(self.values)
            self.values.append(v)
            self._index[v] = i
        return i

    def get(self, ip):
        rs = self.v4 if ip.version == 4 else self.v6
        i = rs.find(int(ip))
        return None if i is None else self.values[i]


class GeoDB:
    def __init__(self, country_csv=None, asn_csv=None):
        self._country = _Table(country_csv)
        self._asn = _Table(asn_csv)

    def lookup(self, ip) -> dict:
        out = {"country": "??", "region": "??", "asn": 0, "as_org": ""}
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return out
        c = self._country.get(addr)
        if c and c[0].upper() not in ("ZZ", ""):
            out["country"] = c[0].upper()
            out["region"] = region_for(c[0])
        a = self._asn.get(addr)
        if a:
            try:
                out["asn"] = int(a[0])
            except ValueError:
                pass
            out["as_org"] = a[1] if len(a) > 1 else ""
        return out


def ip_hash(ip, salt: bytes) -> str:
    return to_hex(ckb_blake2b(salt + ip.encode()))


def load_or_create_salt(path) -> bytes:
    try:
        with open(path, "r", encoding="ascii") as f:
            return from_hex(f.read().strip())
    except FileNotFoundError:
        pass
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    salt = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(salt.hex() + "\n")
    os.chmod(path, 0o600)
    return salt
