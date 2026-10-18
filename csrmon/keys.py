"""Monitor key file."""
import os

from . import crypto
from .hashing import from_hex, to_hex


class KeyFileError(Exception):
    pass


def load_or_create_secret(path) -> bytes:
    path = os.fspath(path)
    if not os.path.exists(path):
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        secret = crypto.generate_secret()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(to_hex(secret) + "\n")
        os.chmod(path, 0o600)
        return secret
    if os.stat(path).st_mode & 0o077:
        raise KeyFileError(f"key file {path} must not be accessible by group/other")
    try:
        with open(path, "r") as f:
            secret = from_hex(f.read().strip())
        crypto.pubkey_from_secret(secret)
    except (ValueError, OSError) as e:
        raise KeyFileError(f"invalid key file {path}") from e
    return secret
