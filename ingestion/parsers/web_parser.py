"""Web Access Log Parser (Apache/Nginx Combined and Common Formats)."""

import ipaddress
import re
from datetime import datetime, timezone
from typing import Optional
from dateutil import parser as date_parser

from ingestion.schema import EventCategory, EventOutcome, NormalizedEvent


# Standard Combined Log Format Regex
# e.g.: 192.168.1.100 - admin [05/Nov/2026:01:23:45 +0000] "GET /index.php?id=1 HTTP/1.1" 200 4512 "http://example.com" "sqlmap/1.7"
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[\w:/]+\s[+\-]\d{4})\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<url>\S+)(?:\s+HTTP/\d\.\d)?"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>.*?)"\s+"(?P<user_agent>.*?)")?'
)


def parse_combined_web_log(line: str, log_source: str = "web_access") -> Optional[NormalizedEvent]:
    """Parse a single Combined Log Format line into a NormalizedEvent."""
    clean_line = line.strip()
    if not clean_line or clean_line.startswith("#"):
        return None

    match = COMBINED_LOG_REGEX.match(clean_line)
    if not match:
        return None

    data = match.groupdict()

    # Validate IP address
    try:
        ipaddress.ip_address(data["ip"].strip())
    except (ValueError, AttributeError):
        return None

    # Parse timestamp: e.g. "05/Nov/2026:01:23:45 +0000"
    ts_str = data["timestamp"].replace(":", " ", 1)
    try:
        dt = date_parser.parse(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
    except Exception:
        # Reject line if timestamp is fundamentally malformed so fallback parser can flag it
        return None

    status_code = int(data["status"])
    outcome = EventOutcome.SUCCESS if status_code < 400 else EventOutcome.FAILURE

    user_name = None if data.get("user") in ("-", "", None) else data.get("user")
    user_agent = data.get("user_agent") if data.get("user_agent") != "-" else None

    return NormalizedEvent(
        timestamp=dt,
        event_category=EventCategory.WEB,
        event_action="http_request",
        event_outcome=outcome,
        source_ip=data["ip"],
        http_method=data["method"],
        http_url=data["url"],
        http_status_code=status_code,
        http_user_agent=user_agent,
        user_name=user_name,
        log_source=log_source,
        raw_event=clean_line,
    )
