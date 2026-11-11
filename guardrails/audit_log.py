"""Tamper-Evident SHA-256 Hash-Chain Audit Log.

Every event appended to the log includes the SHA-256 hash of the
previous entry, forming a blockchain-style chain.  Any post-hoc
modification of a log entry is detectable by ``verify_chain()``.

Storage: append-only JSONL file at ``data/audit_log.jsonl``
(configurable via the ``AUDIT_LOG_PATH`` environment variable or the
``log_path`` constructor argument).

Genesis block convention: the very first entry uses
``prev_hash = "0" * 64`` (64 zeros).
"""

import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Tuple

from pydantic import BaseModel, Field

GENESIS_HASH: str = "0" * 64
DEFAULT_LOG_PATH: str = os.getenv(
    "AUDIT_LOG_PATH", str(Path("data") / "audit_log.jsonl")
)


class AuditEntry(BaseModel):
    """A single entry in the tamper-evident audit log.

    Attributes:
        entry_id: Unique UUID for this entry.
        timestamp: UTC time when the entry was appended.
        entry_type: Semantic category — ``"alert"``, ``"triage"``, or
            ``"approval"``.
        payload: Arbitrary JSON-serialisable event data.
        prev_hash: SHA-256 hash of the immediately preceding entry
            (``"0"*64`` for the genesis block).
        entry_hash: SHA-256 of ``prev_hash + canonical_payload_json``.
            Computed by :meth:`AuditLog.append`; set to empty string
            until hashing occurs.
    """

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    entry_type: str  # "alert" | "triage" | "approval"
    payload: dict[str, Any]
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""


def _compute_hash(prev_hash: str, payload: dict[str, Any]) -> str:
    """Return SHA-256(prev_hash + canonical_payload_json).

    The payload is serialized with sorted keys and no extra whitespace
    to guarantee determinism across Python versions.

    Args:
        prev_hash: Hash of the previous entry.
        payload: Arbitrary dict to include in the hash input.

    Returns:
        Lowercase hex-encoded SHA-256 digest.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    raw = (prev_hash + canonical).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class AuditLog:
    """Append-only, tamper-evident audit log backed by a JSONL file.

    Args:
        log_path: Path to the ``.jsonl`` file.  Created automatically
            (including parent directories) on first append.
    """

    def __init__(self, log_path: str = DEFAULT_LOG_PATH) -> None:
        self._path = Path(log_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, entry_type: str, payload: dict[str, Any]) -> AuditEntry:
        """Append a new entry to the log and return it.

        The ``entry_hash`` and ``prev_hash`` fields are computed here.
        The entry is serialized as a single JSON line and appended to
        the JSONL file.

        Args:
            entry_type: Semantic label for this event.
            payload: Arbitrary data to record (must be JSON-serialisable).

        Returns:
            The completed :class:`AuditEntry` including both hashes.
        """
        prev_hash = self._last_hash()
        entry = AuditEntry(
            entry_type=entry_type,
            payload=payload,
            prev_hash=prev_hash,
        )
        entry.entry_hash = _compute_hash(prev_hash, payload)

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(entry.model_dump_json() + "\n")

        return entry

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """Verify the integrity of the entire hash chain.

        Re-computes every ``entry_hash`` from scratch and compares it
        to the stored value.  Also verifies that each ``prev_hash``
        matches the previous entry's ``entry_hash``.

        Returns:
            A tuple ``(valid, broken_at_index)`` where:

            - ``valid`` is ``True`` iff all entries pass validation.
            - ``broken_at_index`` is the 0-based index of the first
              corrupted entry, or ``None`` if the chain is valid.
        """
        entries = self._load_all()
        expected_prev = GENESIS_HASH

        for idx, entry in enumerate(entries):
            # Check prev_hash linkage.
            if entry.prev_hash != expected_prev:
                return False, idx
            # Recompute and compare entry_hash.
            expected_hash = _compute_hash(entry.prev_hash, entry.payload)
            if entry.entry_hash != expected_hash:
                return False, idx
            expected_prev = entry.entry_hash

        return True, None

    def load_all(self) -> list[AuditEntry]:
        """Return all entries in chronological order."""
        return self._load_all()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _last_hash(self) -> str:
        """Return the ``entry_hash`` of the last persisted entry."""
        entries = self._load_all()
        if not entries:
            return GENESIS_HASH
        return entries[-1].entry_hash

    def _load_all(self) -> list[AuditEntry]:
        """Parse the JSONL file and return a list of :class:`AuditEntry`."""
        if not self._path.exists():
            return []
        entries: list[AuditEntry] = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(AuditEntry.model_validate_json(line))
        return entries
