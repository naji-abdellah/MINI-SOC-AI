"""Rule and Alert Data Models for MiniSOC-AI Detection Engineering.

Follows Sigma-style declarative specification with explicit MITRE ATT&CK mappings.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


class RuleSeverity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RuleStatus(str, Enum):
    EXPERIMENTAL = "experimental"
    TESTING = "testing"
    STABLE = "stable"


class DetectionType(str, Enum):
    PATTERN = "pattern"          # Pattern match on single events (regex, substring)
    THRESHOLD = "threshold"      # Aggregation over time window (e.g. >= 5 events in 300s)
    CORRELATION = "correlation"  # Cross-event correlation (e.g. failure followed by success)


class MitreAttackMapping(BaseModel):
    """Explicit mapping to MITRE ATT&CK matrix."""
    tactic: str = Field(..., description="MITRE Tactic (e.g., Initial Access, Credential Access)")
    technique_id: str = Field(..., description="MITRE Technique ID (e.g., T1190, T1110.001)")
    technique_name: str = Field(..., description="MITRE Technique Name (e.g., Exploit Public-Facing Application)")


class RuleDetectionSpec(BaseModel):
    """Detection criteria and execution logic."""
    type: DetectionType = Field(default=DetectionType.PATTERN)
    
    # Pattern matching fields (case-insensitive substring or regex)
    url_patterns: List[str] = Field(default_factory=list, description="Substrings/regex to match in http_url")
    user_agent_patterns: List[str] = Field(default_factory=list, description="Patterns for http_user_agent")
    raw_patterns: List[str] = Field(default_factory=list, description="Patterns for raw_event")
    http_methods: List[str] = Field(default_factory=list, description="HTTP methods to filter by")
    status_codes: List[int] = Field(default_factory=list, description="HTTP response status codes to filter by")
    event_category: Optional[str] = Field(default=None, description="Event category filter (web, authentication, etc.)")
    event_outcome: Optional[str] = Field(default=None, description="Event outcome filter (success, failure)")
    
    # Threshold / Aggregation fields
    time_window_seconds: int = Field(default=300, description="Sliding time window for aggregations in seconds")
    threshold_count: int = Field(default=1, description="Minimum events needed to trigger alert")
    group_by: List[str] = Field(default_factory=lambda: ["source_ip"], description="Fields to group aggregation by")

    # Custom SQL override for advanced correlations
    custom_sql: Optional[str] = Field(default=None, description="Direct DuckDB SQL query for complex correlations")


class DetectionRule(BaseModel):
    """Sigma-style Detection Rule specification."""
    id: str = Field(..., description="Unique rule identifier (e.g., soc-rule-sqli-001)")
    title: str = Field(..., description="Human-readable rule title")
    description: str = Field(..., description="Detailed technical description and threat narrative")
    author: str = Field(default="Naji Abdellah")
    status: RuleStatus = Field(default=RuleStatus.STABLE)
    severity: RuleSeverity = Field(default=RuleSeverity.MEDIUM)
    references: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    mitre: MitreAttackMapping
    detection: RuleDetectionSpec
    falsepositives: List[str] = Field(default_factory=list)


class AlertStatus(str, Enum):
    NEW = "new"
    IN_TRIAGE = "in_triage"
    ESCALATED = "escalated"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class Alert(BaseModel):
    """Generated Security Alert stored in alerts table."""
    alert_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_id: str
    rule_title: str
    severity: RuleSeverity
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique_name: str
    source_ip: Optional[str] = None
    target_user: Optional[str] = None
    matched_event_ids: List[str] = Field(default_factory=list)
    event_count: int = 1
    evidence: str
    status: AlertStatus = Field(default=AlertStatus.NEW)

    def to_duckdb_row(self) -> Dict[str, Any]:
        """Flatten for DuckDB alerts table."""
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "severity": self.severity.value,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique_id": self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "source_ip": self.source_ip,
            "target_user": self.target_user,
            "matched_event_ids": self.matched_event_ids,
            "event_count": self.event_count,
            "evidence": self.evidence,
            "status": self.status.value,
        }
