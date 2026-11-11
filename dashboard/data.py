"""Dashboard data layer — queries DuckDB for all dashboard views.

All functions return plain Python dicts/lists so the Streamlit layer
stays decoupled from the database.  Each function opens a fresh
read-only connection to avoid interfering with write operations from
the ingestion or detection pipeline.
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any

import duckdb
import pandas as pd

_DEFAULT_DB = os.getenv("MINISOC_DB", "data/minisoc.duckdb")


def _conn(db_path: str = _DEFAULT_DB) -> duckdb.DuckDBPyConnection:
    """Return a fresh read-only DuckDB connection."""
    return duckdb.connect(db_path, read_only=True)


# ---------------------------------------------------------------------------
# Alert volume
# ---------------------------------------------------------------------------

def alert_volume_by_hour(db_path: str = _DEFAULT_DB) -> pd.DataFrame:
    """Return alert counts grouped by UTC hour.

    Columns: ``hour`` (datetime), ``count`` (int).
    """
    try:
        con = _conn(db_path)
        df = con.execute(
            """
            SELECT
                date_trunc('hour', detected_at) AS hour,
                COUNT(*)                         AS count
            FROM   alerts
            GROUP  BY 1
            ORDER  BY 1
            """
        ).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame(columns=["hour", "count"])


def alert_severity_counts(db_path: str = _DEFAULT_DB) -> pd.DataFrame:
    """Return alert counts by severity level.

    Columns: ``severity``, ``count``.
    """
    try:
        con = _conn(db_path)
        df = con.execute(
            """
            SELECT severity, COUNT(*) AS count
            FROM   alerts
            GROUP  BY severity
            ORDER  BY count DESC
            """
        ).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame(columns=["severity", "count"])


def recent_alerts(db_path: str = _DEFAULT_DB, limit: int = 50) -> pd.DataFrame:
    """Return the *limit* most recent alerts.

    Columns: ``alert_id``, ``rule_id``, ``severity``, ``detected_at``,
    ``description``.
    """
    try:
        con = _conn(db_path)
        df = con.execute(
            f"""
            SELECT alert_id, rule_id, severity, detected_at,
                   description
            FROM   alerts
            ORDER  BY detected_at DESC
            LIMIT  {int(limit)}
            """
        ).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame(
            columns=["alert_id", "rule_id", "severity", "detected_at", "description"]
        )


# ---------------------------------------------------------------------------
# MITRE ATT&CK coverage
# ---------------------------------------------------------------------------

def mitre_coverage(db_path: str = _DEFAULT_DB) -> pd.DataFrame:
    """Return alert counts grouped by MITRE technique ID.

    Columns: ``mitre_technique_id``, ``count``.
    Falls back to a static mapping from rule names when the alerts
    table has no ``mitre_technique_id`` column.
    """
    _RULE_TO_MITRE: dict[str, str] = {
        "sqli_error_or_union": "T1190",
        "path_traversal_lfi": "T1083",
        "ssh_brute_force": "T1110",
        "web_login_brute_force": "T1110",
        "os_command_injection": "T1059",
        "scanner_user_agents": "T1046",
        "sensitive_file_probing": "T1083",
        "xss_script_injection": "T1059",
        "admin_access_after_brute_force": "T1078",
        "sensitive_os_credential_access": "T1003",
    }
    try:
        con = _conn(db_path)
        rows = con.execute(
            "SELECT rule_id, COUNT(*) AS cnt FROM alerts GROUP BY rule_id"
        ).fetchall()
        con.close()
        records: dict[str, int] = {}
        for rule_id, cnt in rows:
            mid = _RULE_TO_MITRE.get(rule_id, "T0000")
            records[mid] = records.get(mid, 0) + cnt
        df = pd.DataFrame(
            [{"mitre_technique_id": k, "count": v} for k, v in records.items()]
        ).sort_values("count", ascending=False)
        return df
    except Exception:
        return pd.DataFrame(columns=["mitre_technique_id", "count"])


# ---------------------------------------------------------------------------
# Approval queue
# ---------------------------------------------------------------------------

def pending_approvals(db_path: str = _DEFAULT_DB) -> pd.DataFrame:
    """Return all pending approval requests.

    Columns: ``request_id``, ``alert_id``, ``suggested_action``,
    ``timestamp``.
    """
    try:
        con = _conn(db_path)
        df = con.execute(
            """
            SELECT request_id, alert_id, suggested_action, timestamp
            FROM   approvals
            WHERE  status = 'pending'
            ORDER  BY timestamp ASC
            """
        ).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame(
            columns=["request_id", "alert_id", "suggested_action", "timestamp"]
        )


def approval_history(db_path: str = _DEFAULT_DB, limit: int = 20) -> pd.DataFrame:
    """Return recent approval decisions.

    Columns: ``request_id``, ``alert_id``, ``suggested_action``,
    ``status``, ``analyst``, ``timestamp``.
    """
    try:
        con = _conn(db_path)
        df = con.execute(
            f"""
            SELECT request_id, alert_id, suggested_action,
                   status, analyst, timestamp
            FROM   approvals
            WHERE  status != 'pending'
            ORDER  BY timestamp DESC
            LIMIT  {int(limit)}
            """
        ).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame(
            columns=[
                "request_id", "alert_id", "suggested_action",
                "status", "analyst", "timestamp",
            ]
        )


# ---------------------------------------------------------------------------
# Audit log chain status
# ---------------------------------------------------------------------------

def audit_chain_status(
    log_path: str = os.getenv("AUDIT_LOG_PATH", "data/audit_log.jsonl"),
) -> dict[str, Any]:
    """Return audit-chain verification results.

    Returns a dict with keys:
        ``valid`` (bool), ``entry_count`` (int),
        ``broken_at`` (int | None), ``log_path`` (str).
    """
    from guardrails.audit_log import AuditLog

    log = AuditLog(log_path=log_path)
    entries = log.load_all()
    valid, broken_at = log.verify_chain()
    return {
        "valid": valid,
        "entry_count": len(entries),
        "broken_at": broken_at,
        "log_path": log_path,
    }


# ---------------------------------------------------------------------------
# Analyst feedback
# ---------------------------------------------------------------------------

def store_feedback(
    alert_id: str,
    was_fp: bool,
    comment: str,
    db_path: str = _DEFAULT_DB,
) -> None:
    """Persist analyst feedback for a given alert.

    Creates the ``analyst_feedback`` table if it doesn't exist.

    Args:
        alert_id: The alert being reviewed.
        was_fp: True if the analyst marked the alert as a false positive.
        comment: Free-text analyst note.
        db_path: Path to DuckDB file.
    """
    con = duckdb.connect(db_path)
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS analyst_feedback (
            feedback_id  VARCHAR PRIMARY KEY,
            alert_id     VARCHAR NOT NULL,
            was_fp       BOOLEAN,
            comment      VARCHAR,
            submitted_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    import uuid
    con.execute(
        """
        INSERT INTO analyst_feedback
            (feedback_id, alert_id, was_fp, comment, submitted_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        [str(uuid.uuid4()), alert_id, was_fp, comment,
         datetime.now(timezone.utc)],
    )
    con.close()


def feedback_summary(db_path: str = _DEFAULT_DB) -> pd.DataFrame:
    """Return feedback counts by false-positive flag.

    Columns: ``was_fp``, ``count``.
    """
    try:
        con = _conn(db_path)
        df = con.execute(
            """
            SELECT was_fp, COUNT(*) AS count
            FROM   analyst_feedback
            GROUP  BY was_fp
            """
        ).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame(columns=["was_fp", "count"])
