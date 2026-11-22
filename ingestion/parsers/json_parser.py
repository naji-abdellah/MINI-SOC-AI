"""Structured JSON and Docker Container Log Parser."""

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from dateutil import parser as date_parser

from ingestion.schema import EventCategory, EventOutcome, NormalizedEvent


# Pattern for Juice Shop standard HTTP access log line inside Docker JSON 'log' field:
# e.g.: "GET /rest/products/search?q=test 200 15.2 ms - 452"
# or with IP: "::ffff:192.168.1.50 - - [05/Nov/2026:01:23:45 +0000] \"POST /rest/user/login HTTP/1.1\" 401 24"
JUICE_REST_PATTERN = re.compile(
    r'^(?:(?P<ip>\S+)\s+)?'
    r'(?P<method>[A-Z]+)\s+'
    r'(?P<url>\S+)\s+'
    r'(?P<status>\d{3})'
)


def parse_json_log(line: str, log_source: str = "json_log") -> Optional[NormalizedEvent]:
    """Parse structured JSON log or Docker json-file log line."""
    clean_line = line.strip()
    if not clean_line or clean_line.startswith("#"):
        return None

    try:
        data: Dict[str, Any] = json.loads(clean_line)
    except json.JSONDecodeError:
        return None

    # Case 1: Docker daemon wrapper format: {"log": "...", "stream": "stdout", "time": "..."}
    if "log" in data and "time" in data:
        raw_msg = data["log"].strip()
        ts_str = data["time"]
        try:
            parsed_dt = date_parser.parse(ts_str)
            dt = parsed_dt.replace(tzinfo=timezone.utc) if parsed_dt.tzinfo is None else parsed_dt.astimezone(timezone.utc)
        except Exception:
            return None

        # Check if the log message itself is a REST request
        match = JUICE_REST_PATTERN.match(raw_msg)
        if match:
            m = match.groupdict()
            status_code = int(m["status"])
            ip = m.get("ip")
            if ip and ip.startswith("::ffff:"):
                ip = ip.replace("::ffff:", "")
            return NormalizedEvent(
                timestamp=dt,
                event_category=EventCategory.WEB,
                event_action="http_request",
                event_outcome=EventOutcome.SUCCESS if status_code < 400 else EventOutcome.FAILURE,
                source_ip=ip if ip and ip != "-" else None,
                http_method=m["method"],
                http_url=m["url"],
                http_status_code=status_code,
                log_source=log_source or "juiceshop_docker",
                raw_event=clean_line,
            )

        # Generic system log from Docker
        return NormalizedEvent(
            timestamp=dt,
            event_category=EventCategory.SYSTEM,
            event_action="container_stdout",
            event_outcome=EventOutcome.SUCCESS,
            log_source=log_source or "docker",
            raw_event=clean_line,
            extra={"message": raw_msg, "stream": data.get("stream")},
        )

    # Case 2: Direct Structured JSON Event
    # Expected fields: timestamp/@timestamp/time, method, url, status/status_code, ip/source_ip
    ts_field = data.get("@timestamp") or data.get("timestamp") or data.get("time")
    if ts_field:
        try:
            parsed_dt = date_parser.parse(str(ts_field))
            dt = parsed_dt.replace(tzinfo=timezone.utc) if parsed_dt.tzinfo is None else parsed_dt.astimezone(timezone.utc)
        except Exception:
            return None
    else:
        dt = datetime.now(timezone.utc)

    method = data.get("http_method") or data.get("method")
    url = data.get("http_url") or data.get("url")
    status = data.get("http_status_code") or data.get("status")
    ip = data.get("source_ip") or data.get("ip") or data.get("client_ip")
    user = data.get("user_name") or data.get("user") or data.get("username")
    user_agent = data.get("http_user_agent") or data.get("user_agent")

    category = EventCategory.WEB if (method or url) else EventCategory.UNKNOWN
    if "category" in data:
        try:
            category = EventCategory(data["category"])
        except ValueError:
            pass

    status_code = int(status) if status is not None and str(status).isdigit() else None
    outcome = EventOutcome.UNKNOWN
    if status_code is not None:
        outcome = EventOutcome.SUCCESS if status_code < 400 else EventOutcome.FAILURE
    elif "outcome" in data:
        try:
            outcome = EventOutcome(data["outcome"])
        except ValueError:
            pass

    return NormalizedEvent(
        timestamp=dt,
        event_category=category,
        event_action=data.get("action", "http_request" if method else "json_event"),
        event_outcome=outcome,
        source_ip=str(ip) if ip else None,
        http_method=str(method).upper() if method else None,
        http_url=str(url) if url else None,
        http_status_code=status_code,
        http_user_agent=str(user_agent) if user_agent else None,
        user_name=str(user) if user else None,
        log_source=log_source,
        raw_event=clean_line,
        extra={k: v for k, v in data.items() if k not in ("@timestamp", "timestamp", "time", "method", "url", "status", "ip", "user")},
    )
