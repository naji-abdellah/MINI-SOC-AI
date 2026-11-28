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

from filelock import FileLock
from pydantic import BaseModel, Field

GENESIS_HASH: str = "0" * 64
DEFAULT_LOG_PATH: str = os.getenv(
    "AUDIT_LOG_PATH", str(Path("data") / "audit_log.jsonl")
)


class AuditEntry(BaseModel):
    """A single entry in the tamper-evident audit log."""

    entry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    seq: int = 0
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
    entry_id: str,
    entry_type: str,
    timestamp_str: str,
    seq: int = 0,
    secret_key: Optional[str] = None,
) -> str:
    """Return cryptographic hash sealing previous hash, sequence number, metadata, and canonical payload.

    Args:
        prev_hash: Hash of the previous block.
        payload: Arbitrary JSON-serialisable payload dict.
        entry_id: Entry UUID.
        entry_type: Entry type string.
        timestamp_str: Canonical ISO timestamp string.
        seq: Sequence number in chain.
        secret_key: Optional HMAC key for anti-truncation / rewrite protection.

    Returns:
        Lowercase hex-encoded SHA-256 or HMAC-SHA256 digest.
    """
    canonical_payload = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    envelope = f"{prev_hash}|{seq}|{entry_id}|{entry_type}|{timestamp_str}|{canonical_payload}"

    raw = envelope.encode("utf-8")
    key = secret_key or os.getenv("AUDIT_HMAC_KEY")

    if key:
        return hmac.new(key.encode("utf-8"), raw, hashlib.sha256).hexdigest()
    return hashlib.sha256(raw).hexdigest()


class AuditLog:
    """Append-only, tamper-evident audit log backed by a JSONL file with file locking and head checkpoint."""

    def __init__(
        self,
        log_path: str = DEFAULT_LOG_PATH,
        secret_key: Optional[str] = None,
    ) -> None:
        self._path = Path(log_path)
        self._checkpoint_path = Path(f"{log_path}.checkpoint")
        self._lock_path = Path(f"{log_path}.lock")
        self._secret_key = secret_key or os.getenv("AUDIT_HMAC_KEY")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def append(self, entry_type: str, payload: dict[str, Any]) -> AuditEntry:
        """Append a new entry to the log under cross-process file lock and return it."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        lock = FileLock(str(self._lock_path), timeout=10.0)
        with lock:
            prev_hash, last_seq = self._last_state()
            new_seq = last_seq + 1
            now_utc = datetime.now(timezone.utc)
            ts_str = now_utc.isoformat()

            entry = AuditEntry(
                entry_id=str(uuid.uuid4()),
                seq=new_seq,
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
                seq=new_seq,
                secret_key=self._secret_key,
            )

            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(entry.model_dump_json() + "\n")

            self._write_checkpoint(entry)
            return entry

    def verify_chain(self, check_checkpoint: bool = True) -> Tuple[bool, Optional[int]]:
        """Verify the integrity of the entire hash chain.

        Re-computes every ``entry_hash`` from scratch and verifies sequence continuity,
        prev_hash linkage, and head checkpoint consistency (tail-truncation defense).
        """
        entries = self._load_all()
        if not entries:
            if check_checkpoint and self._checkpoint_path.exists():
                ckpt = self._read_checkpoint()
                if ckpt and ckpt.get("entry_count", 0) > 0:
                    return False, 0
            return True, None

        expected_prev = GENESIS_HASH
        expected_seq = 1

        for idx, entry in enumerate(entries):
            # 1. Check sequence number and prev_hash linkage
            if entry.seq != expected_seq:
                return False, idx
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
                seq=entry.seq,
                secret_key=self._secret_key,
            )

            if entry.entry_hash != expected_hash:
                return False, idx

            expected_prev = entry.entry_hash
            expected_seq += 1

        # 3. Anti-truncation verification against head checkpoint
        if check_checkpoint and self._checkpoint_path.exists():
            ckpt = self._read_checkpoint()
            if ckpt:
                if len(entries) != ckpt.get("entry_count"):
                    return False, len(entries)
                if entries[-1].entry_hash != ckpt.get("head_hash"):
                    return False, len(entries) - 1

        return True, None

    def load_all(self) -> list[AuditEntry]:
        """Return all entries in chronological order."""
        return self._load_all()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _write_checkpoint(self, entry: AuditEntry) -> None:
        """Write head checkpoint to detect tail truncation."""
        try:
            checkpoint_data = {
                "head_hash": entry.entry_hash,
                "entry_count": entry.seq,
                "timestamp": entry.timestamp.isoformat(),
            }
            self._checkpoint_path.write_text(json.dumps(checkpoint_data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _read_checkpoint(self) -> Optional[dict[str, Any]]:
        """Read head checkpoint if present."""
        if not self._checkpoint_path.exists():
            return None
        try:
            return json.loads(self._checkpoint_path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def _last_state(self) -> Tuple[str, int]:
        """Return (entry_hash, seq) of the last persisted entry efficiently."""
        if not self._path.exists() or self._path.stat().st_size == 0:
            return GENESIS_HASH, 0

        try:
            with self._path.open("rb") as f:
                f.seek(max(0, self._path.stat().st_size - 8192))
                lines = f.read().decode("utf-8", errors="replace").splitlines()
                for line in reversed(lines):
                    line = line.strip()
                    if line:
                        entry = AuditEntry.model_validate_json(line)
                        return entry.entry_hash, entry.seq
        except Exception:
            entries = self._load_all()
            if entries:
                return entries[-1].entry_hash, entries[-1].seq

        return GENESIS_HASH, 0

    def _last_hash(self) -> str:
        """Return the ``entry_hash`` of the last persisted entry."""
        h, _ = self._last_state()
        return h

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
