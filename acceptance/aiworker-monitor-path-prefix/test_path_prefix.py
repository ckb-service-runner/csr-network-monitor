"""The web page works under a path prefix (one hostname, /testnet/ and /mainnet/ in Caddy, D40)."""
import os
import re

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "csrmon", "web")


def read(name):
    with open(os.path.join(WEB, name), encoding="utf-8") as f:
        return f.read()


def test_index_uses_relative_asset_paths():
    html = read("index.html")
    refs = re.findall(r'(?:src|href)="([^"]+)"', html)
    assert refs, "no asset references found"
    for r in refs:
        if r.startswith(("http:", "https:", "data:", "#")):
            continue
        assert not r.startswith("/"), r


def test_app_fetches_relative_api_paths():
    js = read("app.mjs")
    assert not re.search(r"""getJson\(\s*["'`]/""", js)
    for p in ("v1/monitor", "v1/${net}/summary", "v1/${net}/runners", "v1/locations"):
        assert p in js, p
