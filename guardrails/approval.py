"""Human-in-the-Loop Approval Gate.

Every triage report must pass through an analyst approval step before
any automated containment action is executed.  Approval records are
persisted to DuckDB so they survive process restarts.
"""

import uuid
from datetime import datetime, timezone
from typing import Optional

import duckdb
from pydantic import BaseModel, Field

from llm.schemas import AllowedAction, TriageReport

ApprovalStatus = str  # "pending" | "approved" | "rejected"


class ApprovalRequest(BaseModel):
    """An analyst approval request linked to a triage report.

    Attributes:
        request_id: Unique UUID for this approval request.
        alert_id: The alert that was triaged.
        suggested_action: The LLM-suggested containment action.
        analyst_notes: Optional notes captured at approval/rejection.
        status: Current lifecycle state.
        analyst: Identity of the analyst who acted (empty when pending).
        timestamp: UTC wall-clock time of the last state change.
    """

    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    alert_id: str
    suggested_action: AllowedAction
    analyst_notes: str = ""
    status: ApprovalStatus = "pending"
    analyst: str = ""
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class ApprovalGate:
    """Submit, approve, and reject triage reports.

    Approval records are stored in a ``approvals`` table inside the
    given DuckDB database path.

    Args:
        db_path: Path to the DuckDB file.  Uses an in-memory database
            when set to ``":memory:"``.
    """

    _CREATE_TABLE = """
        CREATE TABLE IF NOT EXISTS approvals (
            request_id   VARCHAR PRIMARY KEY,
            alert_id     VARCHAR NOT NULL,
            suggested_action VARCHAR NOT NULL,
            analyst_notes VARCHAR,
            status       VARCHAR NOT NULL,
            analyst      VARCHAR,
            timestamp    TIMESTAMPTZ NOT NULL
        )
    """

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._conn = duckdb.connect(db_path)
        self._conn.execute(self._CREATE_TABLE)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def submit(self, report: TriageReport) -> ApprovalRequest:
        """Create a pending approval request for *report*.

        Args:
            report: The sanitized triage report from the LLM pipeline.

        Returns:
            A newly created :class:`ApprovalRequest` with status
            ``"pending"``.
        """
        req = ApprovalRequest(
            alert_id=report.alert_id,
            suggested_action=report.suggested_action,
        )
        self._upsert(req)
        return req

    def approve(self, request_id: str, analyst: str) -> ApprovalRequest:
        """Mark a pending request as approved.

        Args:
            request_id: ID of the request to approve.
            analyst: Identity string of the approving analyst.

        Returns:
            Updated :class:`ApprovalRequest` with status ``"approved"``.

        Raises:
            KeyError: If *request_id* does not exist.
        """
        req = self._fetch(request_id)
        req.status = "approved"
        req.analyst = analyst
        req.timestamp = datetime.now(timezone.utc)
        self._upsert(req)
        return req

    def reject(
        self, request_id: str, analyst: str, reason: str = ""
    ) -> ApprovalRequest:
        """Mark a pending request as rejected.

        Args:
            request_id: ID of the request to reject.
            analyst: Identity string of the rejecting analyst.
            reason: Human-readable rejection reason stored as notes.

        Returns:
            Updated :class:`ApprovalRequest` with status ``"rejected"``.

        Raises:
            KeyError: If *request_id* does not exist.
        """
        req = self._fetch(request_id)
        req.status = "rejected"
        req.analyst = analyst
        req.analyst_notes = reason
        req.timestamp = datetime.now(timezone.utc)
        self._upsert(req)
        return req

    def get(self, request_id: str) -> ApprovalRequest:
        """Retrieve an approval request by ID.

        Raises:
            KeyError: If not found.
        """
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
                 analyst_notes, status, analyst, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            [
                req.request_id,
                req.alert_id,
                req.suggested_action,
                req.analyst_notes,
                req.status,
                req.analyst,
                req.timestamp,
            ],
        )

    def _fetch(self, request_id: str) -> ApprovalRequest:
        """Load an :class:`ApprovalRequest` from DuckDB by ID."""
        rows = self._conn.execute(
            "SELECT * FROM approvals WHERE request_id = ?", [request_id]
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
        )
