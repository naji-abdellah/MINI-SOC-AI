"""Milestone 2 Break-It Exercise: Detection Evasion & Hardening.

Exercises:
1. Craft URL-encoded path traversal (%2e%2e%2f) to test evasion against naive rules.
2. Craft SQL injection with inline comments (/**/) and mixed casing (uNiOn/**/sElEcT).
3. Demonstrate evasion failure against naive string matching, and evasion defeat with normalized engine.
"""

import duckdb
import pytest
from detections.engine import DetectionEngine
from detections.rule_schema import DetectionRule, DetectionType, MitreAttackMapping, RuleDetectionSpec, RuleSeverity


@pytest.fixture
def evasion_db():
    """Create test DuckDB instance."""
    conn = duckdb.connect(":memory:")
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
    return conn


def test_break_it_url_encoded_traversal_evasion(evasion_db):
    """Break-It Exercise 1: URL-encoded Path Traversal.
    
    Attack payload: %2e%2e%2f%2e%2e%2fetc%2fpasswd (URL-encoded '../')
    Observation: A naive rule searching only for literal '../' misses the attack!
    Resolution: Our engine queries both raw and url_decode(http_url) to catch the evasion.
    """
    conn = evasion_db

    # Insert URL-encoded traversal attack
    conn.execute("""
        INSERT INTO events VALUES (
            'ev-evasion-lfi-1', '2026-11-05 02:00:00+00', 'web', 'http_request', 'success',
            '10.20.30.40', 49152, '10.0.0.1', 80, 'GET',
            '/vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd', 200,
            'Mozilla/5.0', NULL, 'dvwa', 'raw_line', []
        );
    """)

    # 1. Simulate a NAIVE rule (does not use url_decode)
    naive_sql = "SELECT * FROM events WHERE lower(http_url) LIKE '%../%';"
    naive_matches = conn.execute(naive_sql).fetchall()
    # The naive rule completely MISSES the evasion!
    assert len(naive_matches) == 0, "Naive rule should have been evaded by %2e%2e%2f!"

    # 2. Now run our hardened DetectionEngine with soc-rule-lfi-002
    engine = DetectionEngine(db_conn=conn)
    engine.load_rules_from_dir("detections/rules")
    alerts = engine.run_all_rules()

    lfi_alerts = [a for a in alerts if a.rule_id == "soc-rule-lfi-002"]
    # Our engine defeats the evasion and catches the attack!
    assert len(lfi_alerts) == 1
    assert lfi_alerts[0].source_ip == "10.20.30.40"
    assert lfi_alerts[0].mitre_technique_id == "T1083"


def test_break_it_sqli_comment_and_casing_evasion(evasion_db):
    """Break-It Exercise 2: SQL Injection with inline comments and mixed case.
    
    Attack payload: id=1'/**/uNiOn/**/sElEcT/**/null,version()--
    Observation: A naive rule checking for lowercase "union select" with exact space fails.
    Resolution: Enhanced pattern rules include URL-decoded and comment-resilient detection.
    """
    conn = evasion_db

    conn.execute("""
        INSERT INTO events VALUES (
            'ev-evasion-sqli-1', '2026-11-05 02:10:00+00', 'web', 'http_request', 'success',
            '10.20.30.50', 49153, '10.0.0.1', 80, 'GET',
            '/vulnerabilities/sqli/?id=1''/**/uNiOn/**/sElEcT/**/null,version()--', 200,
            'curl/8.4.0', NULL, 'dvwa', 'raw_line', []
        );
    """)

    # Naive rule with exact space matching
    naive_sql = "SELECT * FROM events WHERE lower(http_url) LIKE '%union select%';"
    naive_matches = conn.execute(naive_sql).fetchall()
    assert len(naive_matches) == 0, "Naive rule should fail to match /**/ inline comments!"

    # 2. Run our DetectionEngine with soc-rule-sqli-001
    engine = DetectionEngine(db_conn=conn)
    engine.load_rules_from_dir("detections/rules")
    alerts = engine.run_all_rules()

    sqli_alerts = [a for a in alerts if a.rule_id == "soc-rule-sqli-001"]
    assert len(sqli_alerts) == 1, "Hardened rule engine should catch inline comments and mixed casing!"
    assert sqli_alerts[0].source_ip == "10.20.30.50"
    assert sqli_alerts[0].mitre_technique_id == "T1190"
