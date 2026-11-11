"""Tests for Milestone 5 Tamper-Evident Audit Log.

Covers:
  - Genesis block structure
  - Unmodified chain verification
  - Tamper detection (Break-It exercise)
  - Multi-entry chain linkage
"""

import json
import pytest
from pathlib import Path

from guardrails.audit_log import AuditLog, GENESIS_HASH


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_log(tmp_path: Path) -> AuditLog:
    """Return an AuditLog backed by a temp file (deleted after the test)."""
    return AuditLog(log_path=str(tmp_path / "audit_test.jsonl"))


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_audit_genesis_block(self, tmp_path):
        """First entry must have prev_hash == '0' * 64."""
        log = _fresh_log(tmp_path)
        entry = log.append("alert", {"alert_id": "a-001"})
        assert entry.prev_hash == GENESIS_HASH
        assert len(entry.entry_hash) == 64  # SHA-256 hex

    def test_audit_chain_valid(self, tmp_path):
        """An unmodified chain of 5 entries must verify as valid."""
        log = _fresh_log(tmp_path)
        for i in range(5):
            log.append("alert", {"seq": i})
        valid, broken_at = log.verify_chain()
        assert valid is True
        assert broken_at is None

    def test_audit_chain_linkage(self, tmp_path):
        """Each entry's prev_hash must equal the previous entry's entry_hash."""
        log = _fresh_log(tmp_path)
        for i in range(3):
            log.append("triage", {"seq": i})
        entries = log.load_all()
        assert entries[0].prev_hash == GENESIS_HASH
        assert entries[1].prev_hash == entries[0].entry_hash
        assert entries[2].prev_hash == entries[1].entry_hash

    def test_audit_tamper_detection(self, tmp_path):
        """Corrupting a middle entry must be detected by verify_chain().

        Break-It exercise:
          1. Append 5 entries, verify chain is valid.
          2. Corrupt the 3rd entry (index 2) by flipping one character
             in its payload JSON.
          3. verify_chain() must return (False, 2).
        """
        log_path = tmp_path / "audit_tamper.jsonl"
        log = AuditLog(log_path=str(log_path))

        for i in range(5):
            log.append("alert", {"seq": i, "data": "benign"})

        # Step 1 — verify chain is clean before tampering.
        valid, broken_at = log.verify_chain()
        assert valid is True, "Chain should be valid before tampering"

        # Step 2 — corrupt the 3rd line (index 2).
        lines = log_path.read_text(encoding="utf-8").splitlines()
        raw = json.loads(lines[2])
        # Flip one character in the payload to simulate post-hoc editing.
        original_seq = raw["payload"]["seq"]
        raw["payload"]["seq"] = original_seq + 99  # mutate without updating hash
        lines[2] = json.dumps(raw)
        log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        # Step 3 — verify detects the tamper.
        valid2, broken_at2 = log.verify_chain()
        assert valid2 is False, "Tampered chain must fail verification"
        assert broken_at2 == 2, (
            f"Expected broken_at=2, got {broken_at2}"
        )

    def test_audit_empty_log_is_valid(self, tmp_path):
        """An empty log file (or missing file) must be considered valid."""
        log = _fresh_log(tmp_path)
        valid, broken_at = log.verify_chain()
        assert valid is True
        assert broken_at is None

    def test_audit_entry_types_recorded(self, tmp_path):
        """Different entry_type values are stored and retrieved correctly."""
        log = _fresh_log(tmp_path)
        log.append("alert", {"id": "a1"})
        log.append("triage", {"id": "t1"})
        log.append("approval", {"id": "ap1"})
        entries = log.load_all()
        assert [e.entry_type for e in entries] == ["alert", "triage", "approval"]
