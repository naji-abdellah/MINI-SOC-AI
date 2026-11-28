"""Human-in-the-Loop Approval Gate.

Every triage report must pass through an analyst approval step before
any automated containment action is executed. Approval records are
persisted to DuckDB so they survive process restarts.
Enforces strict state transitions (pending -> approved | rejected).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
import uuid

import duckdb
from pydantic import BaseModel, Field

from llm.schemas import AllowedAction, TriageReport

ApprovalStatus = str  # "pending" | "approved" | "rejected"


class ApprovalRequest(BaseModel):
    """An analyst approval request linked to a triage report."""

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    suggested_action: AllowedAction
    target_entity: Optional[str] = None
    analyst_notes: str = ""
    status: ApprovalStatus = "pending"
    analyst: str = ""
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ApprovalGate:
    """Submit, approve, and reject triage reports."""

    _CREATE_TABLE = """
        CREATE TABLE IF NOT EXISTS approvals (
            request_id   VARCHAR PRIMARY KEY,
            alert_id     VARCHAR NOT NULL,
            suggested_action VARCHAR NOT NULL,
            analyst_notes VARCHAR,
            status       VARCHAR NOT NULL,
            analyst      VARCHAR,
            timestamp    TIMESTAMPTZ NOT NULL,
            target_entity VARCHAR
        )
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._conn = duckdb.connect(db_path)
        self._conn.execute(self._CREATE_TABLE)
        # Migrate table if target_entity column was missing in older schema
        try:
            cols = [r[1].lower() for r in self._conn.execute("PRAGMA table_info('approvals')").fetchall()]
            if "target_entity" not in cols:
                self._conn.execute("ALTER TABLE approvals ADD COLUMN target_entity VARCHAR")
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(
        self,
        report: TriageReport,
        target_entity: Optional[str] = None,
    ) -> ApprovalRequest:
        """Create a pending approval request for *report*, enforcing uniqueness on alert_id."""
        existing = self._conn.execute(
            "SELECT request_id FROM approvals WHERE alert_id = ? AND status = 'pending'",
            [report.alert_id],
        ).fetchall()
        if existing:
            return self._fetch(existing[0][0])

        req = ApprovalRequest(
            alert_id=report.alert_id,
            suggested_action=report.suggested_action,
            target_entity=target_entity,
        )
        self._upsert(req)
        return req

    def close(self) -> None:
        """Close the underlying DuckDB connection cleanly."""
        if hasattr(self, "_conn") and self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def __enter__(self) -> ApprovalGate:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def __del__(self) -> None:
        self.close()

    def approve(self, request_id: str, analyst: str) -> ApprovalRequest:
        """Mark a pending request as approved.

        Raises:
            KeyError: If request_id does not exist.
            ValueError: If request is not in 'pending' status.
        """
        req = self._fetch(request_id)
        if req.status != "pending":
            raise ValueError(
                f"Cannot approve request '{request_id}': status is already '{req.status}'"
            )
        req.status = "approved"
        req.analyst = analyst
        req.timestamp = datetime.now(timezone.utc)
        self._upsert(req)
        return req

    def reject(
        self, request_id: str, analyst: str, reason: str = ""
    ) -> ApprovalRequest:
        """Mark a pending request as rejected.

        Raises:
            KeyError: If request_id does not exist.
            ValueError: If request is not in 'pending' status.
        """
        req = self._fetch(request_id)
        if req.status != "pending":
            raise ValueError(
                f"Cannot reject request '{request_id}': status is already '{req.status}'"
            )
        req.status = "rejected"
        req.analyst = analyst
        req.analyst_notes = reason
        req.timestamp = datetime.now(timezone.utc)
        self._upsert(req)
        return req

    def get(self, request_id: str) -> ApprovalRequest:
        """Retrieve an approval request by ID."""
        return self._fetch(request_id)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _upsert(self, req: ApprovalRequest) -> None:
        """Insert or replace *req* in the DuckDB table."""
        self._conn.execute(
            """
            INSERT OR REPLACE INTO approvals
                (request_id, alert_id, suggested_action,
                 analyst_notes, status, analyst, timestamp, target_entity)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                req.request_id,
                req.alert_id,
                req.suggested_action,
                req.analyst_notes,
                req.status,
                req.analyst,
                req.timestamp,
                req.target_entity,
            ],
        )

    def _fetch(self, request_id: str) -> ApprovalRequest:
        """Load an :class:`ApprovalRequest` from DuckDB by ID."""
        rows = self._conn.execute(
            "SELECT request_id, alert_id, suggested_action, analyst_notes, status, analyst, timestamp, target_entity FROM approvals WHERE request_id = ?",
            [request_id],
        ).fetchall()
        if not rows:
            raise KeyError(f"ApprovalRequest not found: {request_id}")
        row = rows[0]
        return ApprovalRequest(
            request_id=row[0],
            alert_id=row[1],
            suggested_action=row[2],
            analyst_notes=row[3] or "",
            status=row[4],
            analyst=row[5] or "",
            timestamp=row[6],
            target_entity=row[7] if len(row) > 7 else None,
        )
