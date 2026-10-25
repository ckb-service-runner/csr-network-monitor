"""Stateless probe schedule: a keyed hash picks the time inside a slot."""
import hashlib
import hmac


def schedule_secret(monitor_secret: bytes) -> bytes:
    return hmac.new(bytes(monitor_secret), b"csr-schedule", hashlib.sha256).digest()


def _unit(secret, key) -> float:
    d = hmac.new(secret, key.encode(), hashlib.sha256).digest()
    return int.from_bytes(d[:8], "big") / 2.0 ** 64


def planned_time(secret, runner_id, slot, interval, jitter) -> float:
    """Slot centre plus up to +-jitter seconds, clamped inside the slot."""
    u = _unit(secret, f"{runner_id}:{slot}")
    t = slot * interval + interval / 2 + (2 * u - 1) * jitter
    return min(max(t, slot * interval), (slot + 1) * interval - 1e-3)
