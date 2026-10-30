"""mon-docs: the monitor repository's documents describe the current code."""
import os
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(*p):
    return open(os.path.join(ROOT, *p), encoding="utf-8").read()


def tracked():
    out = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True).stdout.split()
    return [f for f in out if f.endswith((".md", ".toml", ".py", ".json")) and not f.startswith("acceptance/")]


def test_no_old_owner():
    assert [f for f in tracked() if "psawyerberlin" in read(f)] == []


def test_install_guide_memory_and_geo_tool():
    t = read("docs", "INSTALL.md")
    assert "50 to 150 MB" not in t
    assert "shrink_city" not in t or os.path.exists(os.path.join(ROOT, "tools", "shrink_city.py"))


def test_protocol_doc_details():
    p = read("docs", "PROTOCOL.md")
    assert "159 bytes" in p
    assert "not paged" in p.lower() or "cursor" in p
    assert "CSR-NODE-IDENTITY-v1" in p


def test_readme_names_the_runner_repo():
    assert "ckb-service-runner/ckb-service-runner" in read("README.md")


def test_first_transfer_not_repeated_as_500():
    for f in ("README.md", os.path.join("docs", "INSTALL.md"), os.path.join("docs", "PROTOCOL.md")):
        assert "500 CKB" not in read(f), f
