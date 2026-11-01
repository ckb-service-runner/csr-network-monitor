"""Map phase 3: the public page draws the world map."""
import os
import re

import pytest

from csrmon import api as api_mod, store as store_mod, config as config_mod

WEB = os.path.join(os.path.dirname(api_mod.__file__), "web")


@pytest.fixture
def api(tmp_path):
    lines = ['network = "testnet"', 'public_url = "https://m.example"',
             f'db_path = "{tmp_path}/t.db"', f'key_path = "{tmp_path}/k.key"']
    (tmp_path / "c.toml").write_text("\n".join(lines) + "\n")
    cfg = config_mod.load_config(str(tmp_path / "c.toml"))
    return api_mod.Api(store_mod.Store(cfg.db_path), cfg, (11).to_bytes(32, "big"))


def read(name):
    return open(os.path.join(WEB, name), encoding="utf-8").read()


def test_index_loads_map_script_first():
    html = read("index.html")
    m1 = re.search(r'<script src="(/)?static/worldmap\.js"></script>', html)
    m2 = re.search(r'<script[^>]+type="module"[^>]+src="(/)?static/app\.mjs"', html)
    assert m1 and m2 and m1.start() < m2.start()
    for i in ("map", "map-info", "map-credit", "other"):
        assert re.search(rf'id="{i}"', html), i
    credit = re.search(r'id="map-credit"[^>]*>([^<]*)<', html).group(1)
    assert "Natural Earth" in credit and "DB-IP" in credit and "CC BY 4.0" in credit


def test_app_uses_map():
    app = read("app.mjs")
    assert "v1/locations" in app
    assert "CSRWorldMap" in app and ".svg(" in app
    assert "countryLabel" in app and "countryList" in app
    assert "map-info" in app
    assert "/summary" in app and "/runners" in app


def test_css_styles_map():
    css = read("style.css")
    for sel in (".wm-c", ".wm-dot", ".wm-shadow"):
        assert sel in css, sel
    assert "prefers-color-scheme: dark" in css


def test_worldmap_served(api):
    status, hdrs, body = api.handle("GET", "/static/worldmap.js", {}, b"", "1.2.3.4")
    assert status == 200 and hdrs["Content-Type"].startswith("text/javascript")
    assert body == open(os.path.join(WEB, "worldmap.js"), "rb").read()


def test_web_budget_and_no_urls():
    total = 0
    for name in sorted(os.listdir(WEB)):
        p = os.path.join(WEB, name)
        if not os.path.isfile(p):
            continue
        total += os.path.getsize(p)
        text = open(p, encoding="utf-8").read()
        # outbound links to the project's GitHub org load nothing; allow them only in <a href>
        text = re.sub(r'<a href="https://github\.com/ckb-service-runner/[\w.-]+"', "<a", text)
        assert not re.search(r"https?://", text), name
        assert "//cdn" not in text and "@import" not in text, name
    assert total < 200_000, total
