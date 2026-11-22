"""Normalized Log Event Schema for MiniSOC-AI.

Inspired by Elastic Common Schema (ECS) and Open Cybersecurity Schema Framework (OCSF).
Enforces uniform typing, timezone normalization (always UTC), and standard field names.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import hashlib
import uuid
from pydantic import BaseModel, Field, field_validator, model_validator


def generate_event_id(raw_event: str, log_source: str = "generic") -> str:
    """Generate stable, deterministic event ID based on raw content and log source."""
    content = f"{log_source}:{raw_event.strip()}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]


class EventCategory(str, Enum):
    WEB = "web"
    AUTHENTICATION = "authentication"
    NETWORK = "network"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class EventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"


class NormalizedEvent(BaseModel):
    """Normalized security log event."""

    @model_validator(mode="before")
    @classmethod
    def set_deterministic_event_id(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if not data.get("event_id"):
                raw = data.get("raw_event")
                src = data.get("log_source", "generic")
                if raw:
                    data["event_id"] = generate_event_id(raw, src)
        return data

    # Event identification and timing
    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique identifier for the normalized event.",
    )
    timestamp: datetime = Field(
        ...,
        alias="@timestamp",
        description="Event timestamp in ISO 8601 format, always normalized to UTC.",
    )
    event_category: EventCategory = Field(
        default=EventCategory.UNKNOWN,
        description="High-level category (web, authentication, network, system).",
    )
    event_action: str = Field(
        default="unknown",
        description="Specific action performed (e.g., http_request, user_login, ssh_attempt).",
    )
    event_outcome: EventOutcome = Field(
        default=EventOutcome.UNKNOWN,
        description="Outcome of the action (success, failure, unknown).",
    )

    # Network identifiers
    source_ip: Optional[str] = Field(
        default=None,
        description="IPv4 or IPv6 address originating the event.",
    )
    source_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Source transport port number.",
    )
    destination_ip: Optional[str] = Field(
        default=None,
        description="Destination IPv4 or IPv6 address.",
    )
    destination_port: Optional[int] = Field(
        default=None,
        ge=0,
        le=65535,
        description="Destination transport port number.",
    )

    # HTTP specific context
    http_method: Optional[str] = Field(
        default=None,
        description="HTTP method (GET, POST, PUT, DELETE, etc.).",
    )
    http_url: Optional[str] = Field(
        default=None,
        description="Requested URI / URL path.",
    )
    http_status_code: Optional[int] = Field(
        default=None,
        ge=100,
        le=599,
        description="HTTP response status code.",
    )
    http_user_agent: Optional[str] = Field(
        default=None,
        description="User-Agent header string.",
    )

    # User context
    user_name: Optional[str] = Field(
        default=None,
        description="Username or user identity associated with the event.",
    )

    # Metadata & Lineage
    log_source: str = Field(
        default="generic",
        description="Originating source service (e.g., juiceshop, dvwa, nginx, auth_log).",
    )
    raw_event: str = Field(
        ...,
        description="Verbatim unparsed log line for evidence integrity.",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Tags attached by parsers or enrichment.",
    )
    extra: Dict[str, Any] = Field(
        default_factory=dict,
        description="Vendor or source-specific extra fields.",
    )

    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
    }

    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_utc(cls, v: Any) -> datetime:
        """Ensure timestamps are timezone-aware and converted to UTC."""
        if isinstance(v, str):
            # Parse ISO 8601 or common formats
            from dateutil import parser
            dt = parser.parse(v)
        elif isinstance(v, (int, float)):
            # Epoch timestamp
            dt = datetime.fromtimestamp(v, tz=timezone.utc)
        elif isinstance(v, datetime):
            dt = v
        else:
            raise ValueError(f"Unsupported timestamp format: {v}")

        if dt.tzinfo is None:
            # If naive, assume UTC
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return dt

    @field_validator("http_method", mode="before")
    @classmethod
    def uppercase_http_method(cls, v: Any) -> Optional[str]:
        if isinstance(v, str):
            return v.strip().upper()
        return v

    def to_duckdb_row(self) -> Dict[str, Any]:
        """Flatten model for DuckDB columnar insertion."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_category": self.event_category.value,
            "event_action": self.event_action,
            "event_outcome": self.event_outcome.value,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "http_method": self.http_method,
            "http_url": self.http_url,
            "http_status_code": self.http_status_code,
            "http_user_agent": self.http_user_agent,
            "user_name": self.user_name,
            "log_source": self.log_source,
            "raw_event": self.raw_event,
            "tags": self.tags,
        }
