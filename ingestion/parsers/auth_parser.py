"""Authentication and Syslog Parser (SSH, PAM, sudo)."""

import re
from datetime import datetime, timezone
from typing import Optional
from dateutil import parser as date_parser

from ingestion.schema import EventCategory, EventOutcome, NormalizedEvent


# SSH Failed Login Regex
SSH_FAILED_REGEX = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'sshd\[(?P<pid>\d+)\]:\s+'
    r'Failed password for (?:invalid user\s+)?(?P<user>\S+)\s+'
    r'from\s+(?P<ip>\S+)\s+'
    r'port\s+(?P<port>\d+)'
)

# SSH Accepted Login Regex
SSH_ACCEPTED_REGEX = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'sshd\[(?P<pid>\d+)\]:\s+'
    r'Accepted (?:password|publickey) for (?P<user>\S+)\s+'
    r'from\s+(?P<ip>\S+)\s+'
    r'port\s+(?P<port>\d+)'
)


def parse_auth_log(line: str, log_source: str = "auth_log", current_year: Optional[int] = None) -> Optional[NormalizedEvent]:
    """Parse standard Linux syslog authentication lines."""
    clean_line = line.strip()
    if not clean_line or clean_line.startswith("#"):
        return None

    year = current_year or datetime.now(timezone.utc).year

    # Check SSH Failed
    match = SSH_FAILED_REGEX.match(clean_line)
    if match:
        m = match.groupdict()
        ts_str = f"{m['timestamp']} {year}"
        try:
            parsed_dt = date_parser.parse(ts_str)
            dt = parsed_dt.replace(tzinfo=timezone.utc) if parsed_dt.tzinfo is None else parsed_dt.astimezone(timezone.utc)
        except Exception:
            return None

        return NormalizedEvent(
            timestamp=dt,
            event_category=EventCategory.AUTHENTICATION,
            event_action="user_login",
            event_outcome=EventOutcome.FAILURE,
            source_ip=m["ip"],
            source_port=int(m["port"]),
            user_name=m["user"],
            log_source=log_source,
            raw_event=clean_line,
            tags=["ssh", "auth_failure"],
        )

    # Check SSH Accepted
    match = SSH_ACCEPTED_REGEX.match(clean_line)
    if match:
        m = match.groupdict()
        ts_str = f"{m['timestamp']} {year}"
        try:
            parsed_dt = date_parser.parse(ts_str)
            dt = parsed_dt.replace(tzinfo=timezone.utc) if parsed_dt.tzinfo is None else parsed_dt.astimezone(timezone.utc)
        except Exception:
            return None

        return NormalizedEvent(
            timestamp=dt,
            event_category=EventCategory.AUTHENTICATION,
            event_action="user_login",
            event_outcome=EventOutcome.SUCCESS,
            source_ip=m["ip"],
            source_port=int(m["port"]),
            user_name=m["user"],
            log_source=log_source,
            raw_event=clean_line,
            tags=["ssh", "auth_success"],
        )

    return None
