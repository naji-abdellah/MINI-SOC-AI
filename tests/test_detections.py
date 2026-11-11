"""Unit tests for MiniSOC-AI Detection Engineering & MITRE ATT&CK Rules."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError
import duckdb

from ingestion.schema import EventCategory, EventOutcome, NormalizedEvent
from ingestion.duckdb_store import DuckDBStore
from detections.rule_schema import (
    DetectionRule,
    DetectionType,
    MitreAttackMapping,
    RuleDetectionSpec,
    RuleSeverity,
)
from detections.engine import DetectionEngine


@pytest.fixture
def test_engine():
    """Create an in-memory DuckDB instance and DetectionEngine."""
    conn = duckdb.connect(":memory:")
    # Initialize events table via DuckDBStore
    store = DuckDBStore(db_path=":memory:")
    # Share connection or create tables directly
    conn.execute("""
        CREATE TABLE events (
            event_id VARCHAR PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL,
            event_category VARCHAR NOT NULL,
            event_action VARCHAR NOT NULL,
            event_outcome VARCHAR NOT NULL,
            source_ip VARCHAR,
            source_port INTEGER,
            destination_ip VARCHAR,
            destination_port INTEGER,
            http_method VARCHAR,
            http_url VARCHAR,
            http_status_code INTEGER,
            http_user_agent VARCHAR,
            user_name VARCHAR,
            log_source VARCHAR NOT NULL,
            raw_event VARCHAR NOT NULL,
            tags VARCHAR[]
        );
    """)
    engine = DetectionEngine(db_conn=conn)
    engine.load_rules_from_dir("detections/rules")
    return engine, conn


def test_rule_schema_validation():
    """Verify rule model enforces MITRE mappings and valid syntax."""
    # Valid rule
    rule = DetectionRule(
        id="test-rule-001",
        title="Test SQL Injection",
        description="Detects SQLi in test",
        severity=RuleSeverity.HIGH,
        mitre=MitreAttackMapping(
            tactic="Initial Access",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
        ),
        detection=RuleDetectionSpec(
            type=DetectionType.PATTERN,
            url_patterns=["union select"],
        ),
    )
    assert rule.id == "test-rule-001"
    assert rule.mitre.technique_id == "T1190"

    # Invalid rule: missing MITRE mapping
    with pytest.raises(ValidationError):
        DetectionRule(
            id="test-broken-rule",
            title="Broken Rule",
            description="Missing MITRE",
            detection=RuleDetectionSpec(url_patterns=["test"]),
        )


def test_positive_sqli_detection(test_engine):
    """Verify SQL injection probe triggers soc-rule-sqli-001."""
    engine, conn = test_engine
    conn.execute("""
        INSERT INTO events VALUES (
            'ev-sqli-1', '2026-11-05 01:00:00+00', 'web', 'http_request', 'success',
            '10.10.10.5', 44321, '10.0.0.1', 80, 'GET',
            '/vulnerabilities/sqli/?id=1'' UNION SELECT null,version()--', 200,
            'Mozilla/5.0', NULL, 'dvwa', 'raw_line', []
        );
    """)

    alerts = engine.run_all_rules()
    sqli_alerts = [a for a in alerts if a.rule_id == "soc-rule-sqli-001"]

    assert len(sqli_alerts) == 1
    alert = sqli_alerts[0]
    assert alert.mitre_technique_id == "T1190"
    assert alert.mitre_tactic == "Initial Access"
    assert alert.source_ip == "10.10.10.5"
    assert "UNION SELECT" in alert.evidence


def test_positive_path_traversal_detection(test_engine):
    """Verify LFI/path traversal triggers soc-rule-lfi-002."""
    engine, conn = test_engine
    conn.execute("""
        INSERT INTO events VALUES (
            'ev-lfi-1', '2026-11-05 01:05:00+00', 'web', 'http_request', 'success',
            '10.10.10.6', 44322, '10.0.0.1', 80, 'GET',
            '/vulnerabilities/fi/?page=../../../../etc/passwd', 200,
            'curl/8.4.0', NULL, 'dvwa', 'raw_line', []
        );
    """)

    alerts = engine.run_all_rules()
    lfi_alerts = [a for a in alerts if a.rule_id == "soc-rule-lfi-002"]

    assert len(lfi_alerts) == 1
    assert lfi_alerts[0].mitre_technique_id == "T1083"
    assert lfi_alerts[0].source_ip == "10.10.10.6"


def test_positive_ssh_brute_force_threshold(test_engine):
    """Verify multiple SSH failures from same IP trigger soc-rule-auth-003."""
    engine, conn = test_engine
    # Insert 4 failed attempts from IP 10.10.10.7
    for i in range(4):
        conn.execute(f"""
            INSERT INTO events VALUES (
                'ev-ssh-{i}', '2026-11-05 01:10:0{i}+00', 'authentication', 'user_login', 'failure',
                '10.10.10.7', 38200 + {i}, '10.0.0.1', 22, NULL,
                NULL, NULL, NULL, 'root', 'sshd', 'raw_ssh_fail', ['ssh', 'auth_failure']
            );
        """)

    alerts = engine.run_all_rules()
    ssh_alerts = [a for a in alerts if a.rule_id == "soc-rule-auth-003"]

    assert len(ssh_alerts) == 1
    assert ssh_alerts[0].mitre_technique_id == "T1110.001"
    assert ssh_alerts[0].event_count == 4
    assert ssh_alerts[0].source_ip == "10.10.10.7"


def test_positive_command_injection_detection(test_engine):
    """Verify OS command injection triggers soc-rule-exec-005."""
    engine, conn = test_engine
    conn.execute("""
        INSERT INTO events VALUES (
            'ev-cmdi-1', '2026-11-05 01:15:00+00', 'web', 'http_request', 'success',
            '10.10.10.8', 50123, '10.0.0.1', 80, 'POST',
            '/vulnerabilities/exec/?ip=127.0.0.1;cat /etc/passwd', 200,
            'Mozilla/5.0', NULL, 'dvwa', 'raw_line', []
        );
    """)

    alerts = engine.run_all_rules()
    cmdi_alerts = [a for a in alerts if a.rule_id == "soc-rule-exec-005"]

    assert len(cmdi_alerts) == 1
    assert cmdi_alerts[0].mitre_technique_id == "T1059"


def test_positive_scanner_user_agent_detection(test_engine):
    """Verify automated scanner user agent triggers soc-rule-recon-006."""
    engine, conn = test_engine
    conn.execute("""
        INSERT INTO events VALUES (
            'ev-scan-1', '2026-11-05 01:20:00+00', 'web', 'http_request', 'failure',
            '10.10.10.9', 51000, '10.0.0.1', 80, 'GET',
            '/admin/config.php', 403, 'sqlmap/1.7.2#stable', NULL, 'dvwa', 'raw_line', []
        );
    """)

    alerts = engine.run_all_rules()
    scanner_alerts = [a for a in alerts if a.rule_id == "soc-rule-recon-006"]

    assert len(scanner_alerts) == 1
    assert scanner_alerts[0].mitre_technique_id == "T1595.002"


def test_negative_benign_traffic_no_alerts(test_engine):
    """Verify completely benign browsing causes ZERO false-positive alerts."""
    engine, conn = test_engine
    conn.execute("""
        INSERT INTO events VALUES (
            'ev-benign-1', '2026-11-05 01:25:00+00', 'web', 'http_request', 'success',
            '10.10.10.10', 52000, '10.0.0.1', 80, 'GET',
            '/products/search?q=running+shoes', 200,
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0', 'john_doe', 'store', 'raw_line', []
        );
    """)

    alerts = engine.run_all_rules()
    # No rule should trigger on this benign event
    benign_alerts = [a for a in alerts if "ev-benign-1" in a.matched_event_ids]
    assert len(benign_alerts) == 0


def test_alert_generation_idempotency(test_engine):
    """Verify repeated execution does not insert duplicate alerts in the table."""
    engine, conn = test_engine
    conn.execute("""
        INSERT INTO events VALUES (
            'ev-xss-1', '2026-11-05 01:30:00+00', 'web', 'http_request', 'success',
            '10.10.10.11', 53000, '10.0.0.1', 80, 'GET',
            '/search?q=<script>alert(1)</script>', 200,
            'Mozilla/5.0', NULL, 'web', 'raw_line', []
        );
    """)

    # First run
    alerts_run1 = engine.run_all_rules()
    cur1 = conn.cursor()
    count_run1 = cur1.execute("SELECT count(*) FROM alerts;").fetchall()[0][0]
    cur1.close()

    # Second run on identical data
    alerts_run2 = engine.run_all_rules()
    cur2 = conn.cursor()
    count_run2 = cur2.execute("SELECT count(*) FROM alerts;").fetchall()[0][0]
    cur2.close()

    assert count_run1 == count_run2, "Alert store should be idempotent across runs"
