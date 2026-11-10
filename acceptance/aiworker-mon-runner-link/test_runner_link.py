"""mon-runner-link: /?runner=<id> pre-fills the runner filter and highlights the row."""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


def test_app_reads_the_runner_parameter():
    a = read("csrmon", "web", "app.mjs")
    assert "URLSearchParams" in a
    assert re.search(r"""get\(\s*["']runner["']\s*\)""", a)
    assert "{64}" in a  # the runner ID is checked as 0x + 64 hex


def test_row_is_highlighted_and_scrolled_into_view():
    a = read("csrmon", "web", "app.mjs")
    assert "runner-highlight" in a
    assert "scrollIntoView" in a
    assert "runner-highlight" in read("csrmon", "web", "style.css")


def test_not_found_hint():
    assert "not in the ranking yet" in read("csrmon", "web", "app.mjs")


def test_documented():
    assert "?runner=" in read("docs", "PROTOCOL.md") + read("README.md")
