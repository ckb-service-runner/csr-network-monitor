# A8: the registry owner may differ from the deposit owner (CSR registers with the runner's own lock; the
# csr-registry contract checks the deposit owner's signed consent). Documentation of the change.
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_protocol_and_decisions_mention_the_consent():
    protocol = (ROOT / "docs" / "PROTOCOL.md").read_text()
    assert "consent" in protocol.lower()
    assert "CSR-STAKE-CONSENT-v1" in protocol
    decisions = (ROOT / "DECISIONS.md").read_text()
    assert "D-A8-1" in decisions


def test_scan_no_longer_compares_the_owner():
    src = (ROOT / "csrmon" / "configcell.py").read_text()
    assert "owner_lock_hash=" not in src, "scan_registry must not pass owner_lock_hash to check_stake any more"
