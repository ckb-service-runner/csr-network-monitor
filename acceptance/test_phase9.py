"""Phase 9 acceptance (Python part): the public page is served by the API."""
import os
import re

import pytest

from csrmon import api as api_mod, store as store_mod, config as config_mod

WEB = os.path.join(os.path.dirname(api_mod.__file__), "web")
FILES = ["index.html", "app.mjs", "format.mjs", "style.css"]


@pytest.fixture
def api(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    cfg = config_mod.load_config(str(tmp_path / "c.toml"))
    return api_mod.Api(store_mod.Store(cfg.db_path), cfg, (11).to_bytes(32, "big"))


def get(api, path):
    return api.handle("GET", path, {}, b"", "1.2.3.4")


def test_files_exist_and_small():
    total = 0
    for f in FILES:
        p = os.path.join(WEB, f)
        assert os.path.isfile(p), f
        total += os.path.getsize(p)
    assert total < 200_000


def test_no_external_urls():
    for f in FILES:
        text = open(os.path.join(WEB, f), encoding="utf-8").read()
        assert not re.search(r"https?://", text), f
        assert "//cdn" not in text and "@import" not in text, f


def test_index_served(api):
    status, hdrs, body = get(api, "/")
    assert status == 200 and hdrs["Content-Type"].startswith("text/html")
    html = body.decode()
    for i in ("network-name", "summary", "gate", "map", "ranking", "disclaimer"):
        assert re.search(rf'id="{i}"', html), i
    assert re.search(r'<meta[^>]+name="viewport"', html)
    assert re.search(r'<script[^>]+type="module"[^>]+src="/static/app\.mjs"', html)
    assert re.search(r'<link[^>]+href="/static/style\.css"', html)
    assert "reputation source, not a proof" in html
    assert re.search(r'<table[^>]*>[\s\S]*<thead>[\s\S]*<tbody', html)


def test_static_types(api):
    for name, ctype in (("app.mjs", "text/javascript"), ("format.mjs", "text/javascript"),
                        ("style.css", "text/css")):
        status, hdrs, body = get(api, "/static/" + name)
        assert status == 200 and hdrs["Content-Type"].startswith(ctype), name
        assert body == open(os.path.join(WEB, name), "rb").read()
    app = open(os.path.join(WEB, "app.mjs"), encoding="utf-8").read()
    assert re.search(r"""from\s+["']\./format\.mjs["']""", app)
    assert "/v1/monitor" in app and "/summary" in app and "/runners" in app


def test_static_rejects_other_paths(api):
    for p in ("/static/../api.py", "/static/nope.js", "/static/%2e%2e/api.py", "/static/",
              "/static/sub/x.css", "/index.html.bak", "/api.py"):
        assert get(api, p)[0] == 404, p


def test_static_not_rate_limited(api):
    for _ in range(80):
        assert get(api, "/static/style.css")[0] == 200
