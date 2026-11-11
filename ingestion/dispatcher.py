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


def parse_line(line: str, log_source: str = "generic", fallback_on_unmatched: bool = True) -> Optional[NormalizedEvent]:
    """Attempt to parse a log line using available parser strategies."""
    clean_line = line.strip()
    if not clean_line or clean_line.startswith("#"):
        return None

    # Strategy 1: JSON
    if clean_line.startswith("{") and clean_line.endswith("}"):
        event = parse_json_log(clean_line, log_source=log_source)
        if event:
            return event

    # Strategy 2: Web Combined Log
    event = parse_combined_web_log(clean_line, log_source=log_source)
    if event:
        return event

    # Strategy 3: Auth / Syslog
    event = parse_auth_log(clean_line, log_source=log_source)
    if event:
        return event

    # Strategy 4: Fallback for unparsed/malformed logs
    if fallback_on_unmatched:
        return NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            event_category=EventCategory.UNKNOWN,
            event_action="raw_unparsed",
            event_outcome=EventOutcome.UNKNOWN,
            log_source=log_source,
            raw_event=clean_line,
            tags=["unparsed", "malformed_candidate"],
        )

    return None


def parse_file(file_path: str, log_source: str = "generic") -> Iterator[NormalizedEvent]:
    """Stream and parse a log file line by line."""
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            event = parse_line(line, log_source=log_source)
            if event:
                yield event
