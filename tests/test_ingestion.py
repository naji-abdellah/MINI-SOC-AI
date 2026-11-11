"""Unit tests for MiniSOC-AI Log Normalization and Ingestion Pipeline."""

from datetime import datetime, timezone
import pytest
from ingestion.schema import EventCategory, EventOutcome, NormalizedEvent
from ingestion.parsers.web_parser import parse_combined_web_log
from ingestion.parsers.json_parser import parse_json_log
from ingestion.parsers.auth_parser import parse_auth_log
from ingestion.dispatcher import parse_line
from ingestion.duckdb_store import DuckDBStore


def test_normalized_event_utc_conversion():
    """Verify timestamps are strictly normalized to UTC."""
    # Test 1: String with offset
    event1 = NormalizedEvent(
        timestamp="2026-11-05T03:00:00+02:00",
        raw_event="raw test line 1",
    )
    assert event1.timestamp.tzinfo == timezone.utc
    assert event1.timestamp.hour == 1  # 03:00 +02:00 -> 01:00 UTC

    # Test 2: HTTP method is automatically uppercase
    event2 = NormalizedEvent(
        timestamp=datetime.now(timezone.utc),
        http_method="get",
        raw_event="raw test line 2",
    )
    assert event2.http_method == "GET"


def test_parse_combined_web_log():
    """Verify parsing of Combined Log Format."""
    line = '192.168.1.100 - admin [05/Nov/2026:01:05:00 +0000] "GET /vulnerabilities/sqli/?id=1 HTTP/1.1" 200 5120 "-" "sqlmap/1.7"'
    event = parse_combined_web_log(line, log_source="dvwa")

    assert event is not None
    assert event.source_ip == "192.168.1.100"
    assert event.user_name == "admin"
    assert event.http_method == "GET"
    assert event.http_url == "/vulnerabilities/sqli/?id=1"
    assert event.http_status_code == 200
    assert event.event_outcome == EventOutcome.SUCCESS
    assert event.http_user_agent == "sqlmap/1.7"
    assert event.log_source == "dvwa"


def test_parse_docker_json_log():
    """Verify parsing of Docker container stdout log wrapper."""
    docker_line = '{"log":"::ffff:192.168.1.105 POST /rest/user/login 401 22.1 ms - 32\\n","stream":"stdout","time":"2026-11-05T01:22:02.000000000Z"}'
    event = parse_json_log(docker_line, log_source="juiceshop")

    assert event is not None
    assert event.source_ip == "192.168.1.105"
    assert event.http_method == "POST"
    assert event.http_url == "/rest/user/login"
    assert event.http_status_code == 401
    assert event.event_outcome == EventOutcome.FAILURE


def test_parse_auth_log():
    """Verify parsing of SSH authentication failures and successes."""
    fail_line = "Nov  5 01:30:00 victim sshd[2001]: Failed password for invalid user root from 192.168.1.150 port 38210 ssh2"
    fail_event = parse_auth_log(fail_line, log_source="sshd", current_year=2026)

    assert fail_event is not None
    assert fail_event.event_category == EventCategory.AUTHENTICATION
    assert fail_event.event_outcome == EventOutcome.FAILURE
    assert fail_event.source_ip == "192.168.1.150"
    assert fail_event.user_name == "root"
    assert fail_event.source_port == 38210
    assert "auth_failure" in fail_event.tags

    success_line = "Nov  5 01:35:00 victim sshd[2010]: Accepted password for student from 192.168.1.50 port 49120 ssh2"
    success_event = parse_auth_log(success_line, log_source="sshd", current_year=2026)
    assert success_event is not None
    assert success_event.event_outcome == EventOutcome.SUCCESS
    assert success_event.user_name == "student"


def test_duckdb_store_operations():
    """Verify DuckDB batch insertion, deduplication, and SIEM queries."""
    store = DuckDBStore(db_path=":memory:")

    events = [
        NormalizedEvent(
            timestamp="2026-11-05T01:00:00Z",
            event_category=EventCategory.WEB,
            event_action="http_request",
            event_outcome=EventOutcome.SUCCESS,
            source_ip="10.0.0.1",
            http_method="GET",
            http_url="/index.html",
            http_status_code=200,
            log_source="test",
            raw_event="raw1",
        ),
        NormalizedEvent(
            timestamp="2026-11-05T01:01:00Z",
            event_category=EventCategory.AUTHENTICATION,
            event_action="user_login",
            event_outcome=EventOutcome.FAILURE,
            source_ip="10.0.0.2",
            user_name="admin",
            log_source="test",
            raw_event="raw2",
        ),
        NormalizedEvent(
            timestamp="2026-11-05T01:02:00Z",
            event_category=EventCategory.AUTHENTICATION,
            event_action="user_login",
            event_outcome=EventOutcome.FAILURE,
            source_ip="10.0.0.2",
            user_name="admin",
            log_source="test",
            raw_event="raw3",
        ),
    ]

    inserted = store.insert_events(events)
    assert inserted == 3
    assert store.count_events() == 3

    # Check top IPs
    top_ips = store.get_top_source_ips(limit=5)
    assert len(top_ips) == 2
    assert top_ips[0]["source_ip"] == "10.0.0.2"
    assert top_ips[0]["failure_count"] == 2

    # Check failed login query
    failed = store.get_failed_logins_by_ip(threshold=2)
    assert len(failed) == 1
    assert failed[0]["source_ip"] == "10.0.0.2"
    assert failed[0]["failed_attempts"] == 2

    store.close()
