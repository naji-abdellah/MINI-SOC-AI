"""Unit tests for Local Threat Intelligence Enrichment (ingestion/threat_intel.py)."""

from datetime import datetime, timezone
import pytest
from ingestion.schema import EventCategory, EventOutcome, NormalizedEvent
from ingestion.threat_intel import ThreatIntelService, ThreatIntelIndicator
from ingestion.dispatcher import parse_line


def test_threat_intel_service_lookup():
    ti = ThreatIntelService()
    assert ti.total_indicators >= 5

    match = ti.lookup_ip("198.51.100.4")
    assert match is not None
    assert match.category == "C2_INFRASTRUCTURE"
    assert "APT28" in match.threat_actor

    no_match = ti.lookup_ip("1.1.1.1")
    assert no_match is None


def test_threat_intel_enrich_event():
    ti = ThreatIntelService()
    event = NormalizedEvent(
        timestamp=datetime.now(timezone.utc),
        event_category=EventCategory.WEB,
        event_action="http_request",
        event_outcome=EventOutcome.SUCCESS,
        source_ip="185.220.101.5",
        http_method="GET",
        http_url="/index.php",
        log_source="apache",
        raw_event="raw log",
        tags=["web"],
    )

    enriched = ti.enrich_event(event)
    assert "ti:match" in enriched.tags
    assert "ti:category:TOR_EXIT_NODE" in enriched.tags
    assert "ti:actor:Anonymous" in enriched.tags


def test_dispatcher_with_threat_intel():
    line = '198.51.100.4 - - [05/Nov/2026:01:00:00 +0000] "GET /admin HTTP/1.1" 403 120 "-" "curl/7.68.0"'
    event = parse_line(line, log_source="web", enrich_ti=True)
    assert event is not None
    assert "ti:match" in event.tags
    assert "ti:category:C2_INFRASTRUCTURE" in event.tags
