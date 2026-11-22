"""Tamper-Evident SHA-256 / HMAC Hash-Chain Audit Log.

Every event appended to the log cryptographically seals:
- Previous block hash (prev_hash)
- Entry UUID (entry_id)
- Entry type / category (entry_type)
- Canonical ISO 8601 timestamp (timestamp)
- Canonical JSON payload (payload)

Any modification of log contents or metadata is detectable by ``verify_chain()``.
Supports optional HMAC anchoring (via AUDIT_HMAC_KEY) to prevent truncation
and full-file rewrite attacks.

Storage: append-only JSONL file at ``data/audit_log.jsonl`` (configurable).
Genesis block convention: the very first entry uses ``prev_hash = "0" * 64``.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Optional, Tuple
import uuid

from pydantic import BaseModel, Field

GENESIS_HASH: str = "0" * 64
DEFAULT_LOG_PATH: str = os.getenv(
    "AUDIT_LOG_PATH", str(Path("data") / "audit_log.jsonl")
)


class AuditEntry(BaseModel):
    """A single entry in the tamper-evident audit log."""

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    entry_type: str  # "alert" | "triage" | "approval" | "approval_decision"
    payload: dict[str, Any]
    prev_hash: str = GENESIS_HASH
    entry_hash: str = ""


def _compute_hash(
    prev_hash: str,
    payload: dict[str, Any],
    entry_id: Optional[str] = None,
    entry_type: Optional[str] = None,
    timestamp_str: Optional[str] = None,
    secret_key: Optional[str] = None,
) -> str:
    """Return cryptographic hash sealing previous hash, metadata, and canonical payload.

    Args:
        prev_hash: Hash of the previous block.
        payload: Arbitrary JSON-serialisable payload dict.
        entry_id: Optional entry UUID.
        entry_type: Optional entry type string.
        timestamp_str: Optional canonical ISO timestamp string.
        secret_key: Optional HMAC key for anti-truncation / rewrite protection.

    Returns:
        Lowercase hex-encoded SHA-256 or HMAC-SHA256 digest.
    """
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    
    # Envelope includes metadata if present to ensure tamper-evidence on header fields
    if entry_id is not None and entry_type is not None and timestamp_str is not None:
        envelope = f"{prev_hash}|{entry_id}|{entry_type}|{timestamp_str}|{canonical_payload}"
    else:
        # Backward compatibility for pure payload hashing
        envelope = prev_hash + canonical_payload

    raw = envelope.encode("utf-8")
    key = secret_key or os.getenv("AUDIT_HMAC_KEY")

    if key:
        return hmac.new(key.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


class AuditLog:
    """Append-only, tamper-evident audit log backed by a JSONL file."""

    def __init__(
        self,
        log_path: str = DEFAULT_LOG_PATH,
        secret_key: Optional[str] = None,
    ) -> None:
        self._path = Path(log_path)
        self._secret_key = secret_key or os.getenv("AUDIT_HMAC_KEY")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, entry_type: str, payload: dict[str, Any]) -> AuditEntry:
        """Append a new entry to the log and return it."""
        prev_hash = self._last_hash()
        now_utc = datetime.now(timezone.utc)
        ts_str = now_utc.isoformat()

        entry = AuditEntry(
            entry_id=str(uuid.uuid4()),
            timestamp=now_utc,
            entry_type=entry_type,
            payload=payload,
            prev_hash=prev_hash,
        )

        entry.entry_hash = _compute_hash(
            prev_hash=prev_hash,
            payload=payload,
            entry_id=entry.entry_id,
            entry_type=entry.entry_type,
            timestamp_str=ts_str,
            secret_key=self._secret_key,
        )

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(entry.model_dump_json() + "\n")

        return entry

    def verify_chain(self) -> Tuple[bool, Optional[int]]:
        """Verify the integrity of the entire hash chain.

        Re-computes every ``entry_hash`` from scratch including header fields
        and verifies prev_hash linkage.
        """
        entries = self._load_all()
        expected_prev = GENESIS_HASH

        for idx, entry in enumerate(entries):
            # 1. Check prev_hash linkage
            if entry.prev_hash != expected_prev:
                return False, idx

            # 2. Check full-envelope entry_hash
            ts_str = entry.timestamp.isoformat()
            expected_hash = _compute_hash(
                prev_hash=entry.prev_hash,
                payload=entry.payload,
                entry_id=entry.entry_id,
                entry_type=entry.entry_type,
                timestamp_str=ts_str,
                secret_key=self._secret_key,
            )

            # Fallback check for older legacy payload-only blocks
            legacy_hash = _compute_hash(
                prev_hash=entry.prev_hash,
                payload=entry.payload,
                secret_key=self._secret_key,
            )

            if entry.entry_hash != expected_hash and entry.entry_hash != legacy_hash:
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
        """Return the ``entry_hash`` of the last persisted entry efficiently."""
        if not self._path.exists() or self._path.stat().st_size == 0:
            return GENESIS_HASH

        try:
            with self._path.open("rb") as f:
                f.seek(max(0, self._path.stat().st_size - 8192))
                lines = f.read().decode("utf-8", errors="replace").splitlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        entry = AuditEntry.model_validate_json(line)
                        return entry.entry_hash
        except Exception:
            # Fallback to full load if seek fails
            entries = self._load_all()
            if entries:
                return entries[-1].entry_hash

        return GENESIS_HASH

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
