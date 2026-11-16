"""Dashboard data layer — queries DuckDB for all dashboard views.

All functions return plain Python dicts/lists so the Streamlit layer
stays decoupled from the database. Each function opens a fresh
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


def _get_table_columns(con: duckdb.DuckDBPyConnection, table_name: str) -> set[str]:
    """Return set of column names for a table."""
    try:
        rows = con.execute(f"PRAGMA table_info('{table_name}')").fetchall()
        return {r[1].lower() for r in rows}
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Alert volume
# ---------------------------------------------------------------------------

def alert_volume_by_hour(db_path: str = _DEFAULT_DB) -> pd.DataFrame:
    """Return alert counts grouped by UTC hour.

    Columns: ``hour`` (datetime), ``count`` (int).
    """
    try:
        con = _conn(db_path)
        cols = _get_table_columns(con, "alerts")
        time_col = "timestamp" if "timestamp" in cols else "detected_at" if "detected_at" in cols else None
        if not time_col:
            con.close()
            return pd.DataFrame(columns=["hour", "count"])

        df = con.execute(
            f"""
            SELECT
                date_trunc('hour', {time_col}) AS hour,
                COUNT(*)                        AS count
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

    Columns: ``severity`` (uppercase), ``count``.
    """
    try:
        con = _conn(db_path)
        df = con.execute(
            """
            SELECT UPPER(severity) AS severity, COUNT(*) AS count
            FROM   alerts
            GROUP  BY 1
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
    ``rule_title``, ``description``.
    """
    try:
        con = _conn(db_path)
        cols = _get_table_columns(con, "alerts")
        time_col = "timestamp" if "timestamp" in cols else "detected_at" if "detected_at" in cols else "NULL"
        desc_col = "evidence" if "evidence" in cols else "description" if "description" in cols else "''"
        title_col = "rule_title" if "rule_title" in cols else "rule_id"

        df = con.execute(
            f"""
            SELECT 
                alert_id, 
                rule_id, 
                UPPER(severity) AS severity, 
                {time_col} AS detected_at,
                {title_col} AS rule_title, 
                {desc_col} AS description
            FROM   alerts
            ORDER  BY {time_col} DESC
            LIMIT  {int(limit)}
            """
        ).df()
        con.close()
        return df
    except Exception:
        return pd.DataFrame(
            columns=["alert_id", "rule_id", "severity", "detected_at", "rule_title", "description"]
        )


# ---------------------------------------------------------------------------
# MITRE ATT&CK coverage
# ---------------------------------------------------------------------------

def mitre_coverage(db_path: str = _DEFAULT_DB) -> pd.DataFrame:
    """Return alert counts grouped by MITRE technique ID.

    Columns: ``mitre_technique_id``, ``mitre_technique_name``, ``count``.
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
        cols = _get_table_columns(con, "alerts")
        if "mitre_technique_id" in cols:
            name_expr = "mitre_technique_name" if "mitre_technique_name" in cols else "''"
            df = con.execute(
                f"""
                SELECT 
                    mitre_technique_id, 
                    {name_expr} AS mitre_technique_name, 
                    COUNT(*) AS count 
                FROM alerts 
                GROUP BY 1, 2 
                ORDER BY count DESC
                """
            ).df()
        else:
            rows = con.execute(
                "SELECT rule_id, COUNT(*) AS cnt FROM alerts GROUP BY rule_id"
            ).fetchall()
            records: dict[str, int] = {}
            for rule_id, cnt in rows:
                mid = _RULE_TO_MITRE.get(rule_id, "T0000")
                records[mid] = records.get(mid, 0) + cnt
            df = pd.DataFrame(
                [{"mitre_technique_id": k, "mitre_technique_name": "", "count": v} for k, v in records.items()]
            ).sort_values("count", ascending=False)

        con.close()
        return df
    except Exception:
        return pd.DataFrame(columns=["mitre_technique_id", "mitre_technique_name", "count"])


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
        tables = [t[0] for t in con.execute("SHOW TABLES").fetchall()]
        if "approvals" not in tables:
            con.close()
            return pd.DataFrame(
                columns=["request_id", "alert_id", "suggested_action", "timestamp"]
            )

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
        tables = [t[0] for t in con.execute("SHOW TABLES").fetchall()]
        if "approvals" not in tables:
            con.close()
            return pd.DataFrame(
                columns=[
                    "request_id", "alert_id", "suggested_action",
                    "status", "analyst", "timestamp",
                ]
            )

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


def execute_approval(
    request_id: str,
    action_type: str,
    analyst: str,
    notes: str = "",
    db_path: str = _DEFAULT_DB,
    audit_log_path: str = os.getenv("AUDIT_LOG_PATH", "data/audit_log.jsonl"),
) -> dict[str, Any]:
    """Process an interactive approval or rejection from the dashboard.

    Updates DuckDB, records the action in the cryptographic SHA-256 audit log,
    and returns simulated SOAR containment command execution details.
    """
    from guardrails.approval import ApprovalGate
    from guardrails.audit_log import AuditLog

    gate = ApprovalGate(db_path=db_path)
    if action_type == "approve":
        req = gate.approve(request_id=request_id, analyst=analyst)
    else:
        req = gate.reject(request_id=request_id, analyst=analyst, reason=notes)

    # Simulated SOAR containment response:
    containment_cmd = ""
    if action_type == "approve":
        if req.suggested_action == "block_ip":
            containment_cmd = "SOAR firewall rule applied: iptables -I INPUT 1 -j DROP (source blocked)"
        elif req.suggested_action == "isolate_host":
            containment_cmd = "SOAR network isolation applied: networkctl down interface eth0 (host isolated)"
        elif req.suggested_action == "reset_credentials":
            containment_cmd = "SOAR IAM triggered: pam_tally2 --reset && force_password_reset"
        elif req.suggested_action == "notify_analyst":
            containment_cmd = "SOAR alert broadcasted to SIEM webhook and Slack #soc-incidents"
        else:
            containment_cmd = f"SOAR containment command executed for {req.suggested_action}"
    else:
        containment_cmd = f"Approval rejected by {analyst}. Containment aborted."

    # Cryptographic Audit Log
    audit = AuditLog(log_path=audit_log_path)
    entry = audit.append(
        "approval_decision",
        {
            "request_id": req.request_id,
            "alert_id": req.alert_id,
            "status": req.status,
            "analyst": req.analyst,
            "suggested_action": req.suggested_action,
            "containment_outcome": containment_cmd,
            "analyst_notes": notes,
        },
    )

    return {
        "status": req.status,
        "request_id": req.request_id,
        "containment_cmd": containment_cmd,
        "audit_hash": entry.entry_hash,
    }


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


def audit_log_table(
    log_path: str = os.getenv("AUDIT_LOG_PATH", "data/audit_log.jsonl"),
    limit: int = 25,
) -> pd.DataFrame:
    """Return recent audit log entries formatted as a clean, structured DataFrame for analysts.

    Replaces raw JSON text dumps with a readable forensic timeline.
    """
    from guardrails.audit_log import AuditLog

    log = AuditLog(log_path=log_path)
    entries = log.load_all()
    if not entries:
        return pd.DataFrame(
            columns=["Block", "Timestamp", "Type", "Event Summary", "Parent Hash", "Entry Hash"]
        )

    recent = entries[-limit:][::-1]
    rows = []
    total = len(entries)
    for idx, e in enumerate(recent):
        block_num = total - idx - 1
        p = e.payload
        summary = ""
        if e.entry_type == "approval_decision":
            summary = f"Action {p.get('status', '').upper()}: {p.get('suggested_action', '')} by {p.get('analyst', 'analyst')}"
        elif e.entry_type == "approval":
            summary = f"Queued {p.get('suggested_action', '')} for alert {p.get('alert_id', '')[:8]}"
        elif e.entry_type == "triage":
            rep = p.get("report", {})
            summary = f"AI Triage: {rep.get('mitre_technique_id', '')} - {rep.get('suggested_action', '')} ({rep.get('assessed_severity', '')})"
        elif e.entry_type == "alert":
            summary = f"Rule match: {p.get('rule_id', p.get('alert_id', ''))}"
        else:
            summary = str(p)[:60]

        rows.append(
            {
                "Block": f"#{block_num}",
                "Timestamp": str(e.timestamp)[:19],
                "Type": e.entry_type.upper(),
                "Event Summary": summary,
                "Parent Hash": e.prev_hash[:12] + "...",
                "Entry Hash": e.entry_hash[:12] + "...",
            }
        )
    return pd.DataFrame(rows)


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
        tables = [t[0] for t in con.execute("SHOW TABLES").fetchall()]
        if "analyst_feedback" not in tables:
            con.close()
            return pd.DataFrame(columns=["was_fp", "count"])

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
