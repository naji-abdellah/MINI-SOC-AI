"""Unit tests for dashboard data layer (dashboard/data.py)."""

import os
from datetime import datetime, timezone
from pathlib import Path
import duckdb
import pytest

from dashboard.data import (
    alert_volume_by_hour,
    alert_severity_counts,
    recent_alerts,
    mitre_coverage,
    pending_approvals,
    approval_history,
    audit_chain_status,
    store_feedback,
    feedback_summary,
)
from guardrails.audit_log import AuditLog


@pytest.fixture
def test_db(tmp_path: Path):
    """Sets up a test DuckDB database with mock alerts and approvals."""
    db_file = str(tmp_path / "test_minisoc.duckdb")
    con = duckdb.connect(db_file)

    # Alerts table
    con.execute(
        """
        CREATE TABLE alerts (
            alert_id VARCHAR PRIMARY KEY,
            rule_id VARCHAR NOT NULL,
            severity VARCHAR NOT NULL,
            detected_at TIMESTAMPTZ NOT NULL,
            description VARCHAR NOT NULL,
            matched_event_ids VARCHAR[]
        )
        """
    )
    now = datetime.now(timezone.utc)
    con.execute(
        """
        INSERT INTO alerts VALUES 
        ('a1', 'sqli_error_or_union', 'HIGH', ?, 'SQL injection detected', ['e1']),
        ('a2', 'ssh_brute_force', 'HIGH', ?, 'SSH brute force', ['e2', 'e3']),
        ('a3', 'os_command_injection', 'CRITICAL', ?, 'OS command injection', ['e4']),
        ('a4', 'scanner_user_agents', 'LOW', ?, 'Scanner detected', ['e5'])
        """,
        [now, now, now, now],
    )

    # Approvals table
    con.execute(
        """
        CREATE TABLE approvals (
            request_id VARCHAR PRIMARY KEY,
            alert_id VARCHAR NOT NULL,
            suggested_action VARCHAR NOT NULL,
            analyst_notes VARCHAR,
            status VARCHAR NOT NULL,
            analyst VARCHAR,
            timestamp TIMESTAMPTZ NOT NULL
        )
        """
    )
    con.execute(
        """
        INSERT INTO approvals VALUES
        ('r1', 'a1', 'block_ip', '', 'pending', '', ?),
        ('r2', 'a2', 'block_ip', 'Confirmed attacker IP', 'approved', 'analyst_bob', ?)
        """,
        [now, now],
    )
    con.close()
    return db_file


def test_alert_severity_counts(test_db):
    df = alert_severity_counts(test_db)
    assert not df.empty
    assert "severity" in df.columns
    assert "count" in df.columns
    sevs = dict(zip(df["severity"], df["count"]))
    assert sevs.get("HIGH") == 2
    assert sevs.get("CRITICAL") == 1
    assert sevs.get("LOW") == 1


def test_alert_volume_by_hour(test_db):
    df = alert_volume_by_hour(test_db)
    assert not df.empty
    assert "hour" in df.columns
    assert "count" in df.columns
    assert df["count"].sum() == 4


def test_recent_alerts(test_db):
    df = recent_alerts(test_db, limit=2)
    assert len(df) == 2
    assert "alert_id" in df.columns
    assert "severity" in df.columns


def test_mitre_coverage(test_db):
    df = mitre_coverage(test_db)
    assert not df.empty
    assert "mitre_technique_id" in df.columns
    # sqli -> T1190, ssh -> T1110, cmdi -> T1059, scanner -> T1046
    tech_ids = set(df["mitre_technique_id"])
    assert "T1190" in tech_ids
    assert "T1110" in tech_ids
    assert "T1059" in tech_ids


def test_pending_approvals(test_db):
    df = pending_approvals(test_db)
    assert len(df) == 1
    assert df.iloc[0]["request_id"] == "r1"
    assert df.iloc[0]["suggested_action"] == "block_ip"


def test_approval_history(test_db):
    df = approval_history(test_db)
    assert len(df) == 1
    assert df.iloc[0]["request_id"] == "r2"
    assert df.iloc[0]["status"] == "approved"
    assert df.iloc[0]["analyst"] == "analyst_bob"


def test_audit_chain_status(tmp_path):
    log_file = str(tmp_path / "test_audit.jsonl")
    log = AuditLog(log_path=log_file)
    log.append("alert", {"id": "a1"})
    log.append("triage", {"id": "t1"})

    status = audit_chain_status(log_file)
    assert status["valid"] is True
    assert status["entry_count"] == 2
    assert status["broken_at"] is None


def test_feedback_flow(test_db):
    # Store feedback
    store_feedback("a1", was_fp=False, comment="True positive SQLi", db_path=test_db)
    store_feedback("a4", was_fp=True, comment="Internal vulnerability scanner", db_path=test_db)

    df = feedback_summary(test_db)
    assert len(df) == 2
    records = dict(zip(df["was_fp"], df["count"]))
    assert records[False] == 1
    assert records[True] == 1


def test_empty_or_missing_db(tmp_path):
    missing_db = str(tmp_path / "missing.duckdb")
    df_vol = alert_volume_by_hour(missing_db)
    assert df_vol.empty
    df_sev = alert_severity_counts(missing_db)
    assert df_sev.empty
    df_mitre = mitre_coverage(missing_db)
    assert df_mitre.empty
    df_pend = pending_approvals(missing_db)
    assert df_pend.empty
