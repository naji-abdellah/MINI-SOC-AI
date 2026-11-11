"""Milestone 1 Break-It Exercises.

Exercises:
1. Feed out-of-order logs and verify temporal reconstruction.
2. Feed malformed timestamps, broken JSON, truncated lines, and garbage characters.
3. Feed duplicate events and verify idempotency.
"""

from datetime import datetime, timezone
from pathlib import Path
import pytest
from ingestion.dispatcher import parse_line, parse_file
from ingestion.duckdb_store import DuckDBStore
from ingestion.schema import EventCategory, NormalizedEvent


def test_break_it_out_of_order_events():
    """Verify that inserting events in scrambled order does not break chronological analysis."""
    store = DuckDBStore(db_path=":memory:")

    # Generate events with deliberately inverted timestamps
    t1 = datetime(2026, 11, 5, 1, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 5, 1, 5, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 11, 5, 1, 10, 0, tzinfo=timezone.utc)

    # Ingest in reverse order (T3, then T1, then T2)
    scrambled = [
        NormalizedEvent(timestamp=t3, event_action="step_3", raw_event="e3"),
        NormalizedEvent(timestamp=t1, event_action="step_1", raw_event="e1"),
        NormalizedEvent(timestamp=t2, event_action="step_2", raw_event="e2"),
    ]

    store.insert_events(scrambled)

    # Query ordered by timestamp
    ordered = store.query("SELECT event_action, timestamp FROM events ORDER BY timestamp ASC;")
    assert len(ordered) == 3
    assert ordered[0]["event_action"] == "step_1"
    assert ordered[1]["event_action"] == "step_2"
    assert ordered[2]["event_action"] == "step_3"

    store.close()


def test_break_it_malformed_logs():
    """Feed corrupted and malformed lines to dispatcher; verify zero unhandled exceptions."""
    malformed_samples = [
        # Inverted / invalid date
        '192.168.1.99 - - [99/99/9999:99:99:99 +9999] "GET /broken-date HTTP/1.1" 500 10',
        # Incomplete truncated line
        '192.168.1.99 - - [05/Nov/2026:01:41:00 +0000] "GET /incomplete',
        # Non-numeric status code
        '192.168.1.99 - - [05/Nov/2026:01:42:00 +0000] "POST /upload HTTP/1.1" NOT_A_STATUS 0',
        # Unclosed broken JSON
        '{"timestamp": "2026-11-05T01:45:00Z", "unclosed_json": true',
        # Plain text gibberish
        'THIS IS RANDOM NOISE AND NOT A LOG AT ALL',
    ]

    for line in malformed_samples:
        event = parse_line(line, log_source="break_it_test", fallback_on_unmatched=True)
        # Pipeline must not crash; fallback event must preserve raw data
        assert event is not None
        assert event.raw_event == line
        assert ("unparsed" in event.tags or "malformed_candidate" in event.tags or event.event_category == EventCategory.UNKNOWN)


def test_break_it_malformed_file_ingestion():
    """Ingest the real malformed.log file directly into DuckDB without failure."""
    store = DuckDBStore(db_path=":memory:")
    sample_file = Path("data/samples/malformed.log")
    assert sample_file.exists(), "malformed.log test sample must exist"

    events = list(parse_file(str(sample_file), log_source="malformed_test"))
    assert len(events) > 0

    inserted = store.insert_events(events)
    assert inserted == len(events)
    assert store.count_events() == len(events)

    store.close()
