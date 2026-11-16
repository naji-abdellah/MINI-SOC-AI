"""Log Ingestion Dispatcher.

Directs incoming raw log lines to appropriate specialized parsers and falls back to
safe raw ingestion to preserve evidence integrity.
"""

from datetime import datetime, timezone
from typing import Iterator, List, Optional
from ingestion.schema import EventCategory, EventOutcome, NormalizedEvent
from ingestion.parsers.web_parser import parse_combined_web_log
from ingestion.parsers.json_parser import parse_json_log
from ingestion.parsers.auth_parser import parse_auth_log
from ingestion.threat_intel import ThreatIntelService

_ti_service: Optional[ThreatIntelService] = None


def get_threat_intel_service() -> ThreatIntelService:
    """Lazy loader for ThreatIntelService."""
    global _ti_service
    if _ti_service is None:
        _ti_service = ThreatIntelService()
    return _ti_service


def parse_line(
    line: str,
    log_source: str = "generic",
    fallback_on_unmatched: bool = True,
    enrich_ti: bool = True,
) -> Optional[NormalizedEvent]:
    """Attempt to parse a log line using available parser strategies."""
    clean_line = line.strip()
    if not clean_line or clean_line.startswith("#"):
        return None

    event: Optional[NormalizedEvent] = None

    # Strategy 1: JSON
    if clean_line.startswith("{") and clean_line.endswith("}"):
        event = parse_json_log(clean_line, log_source=log_source)

    # Strategy 2: Web Combined Log
    if not event:
        event = parse_combined_web_log(clean_line, log_source=log_source)

    # Strategy 3: Auth / Syslog
    if not event:
        event = parse_auth_log(clean_line, log_source=log_source)

    # Strategy 4: Fallback for unparsed/malformed logs
    if not event and fallback_on_unmatched:
        event = NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            event_category=EventCategory.UNKNOWN,
            event_action="raw_unparsed",
            event_outcome=EventOutcome.UNKNOWN,
            log_source=log_source,
            raw_event=clean_line,
            tags=["unparsed", "malformed_candidate"],
        )

    # Optional Threat Intelligence enrichment
    if event and enrich_ti:
        event = get_threat_intel_service().enrich_event(event)

    return event


def parse_file(
    file_path: str,
    log_source: str = "generic",
    enrich_ti: bool = True,
) -> Iterator[NormalizedEvent]:
    """Stream and parse a log file line by line."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, log_source=log_source, enrich_ti=enrich_ti)
            if event:
                yield event
