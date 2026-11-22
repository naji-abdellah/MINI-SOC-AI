"""Pydantic Schemas for MiniSOC-AI LLM Triage Output.

Enforces strict JSON typing, enumerated severities, and authorized actions.
"""

from typing import List, Literal
from pydantic import BaseModel, Field


AllowedSeverity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
AllowedAction = Literal[
    "block_ip",
    "isolate_host",
    "reset_credentials",
    "notify_analyst",
    "dismiss_alert",
]


class TriageReport(BaseModel):
    """Structured incident triage assessment produced by local LLM."""

    alert_id: str = Field(..., description="Unique ID of the triaged alert.")
    incident_summary: str = Field(
        ...,
        description="Clear, 1-2 sentence plain-language synthesis of the detected activity.",
    )
    mitre_technique_id: str = Field(
        ...,
        description="Associated MITRE ATT&CK Technique ID (e.g., T1190).",
    )
    mitre_technique_name: str = Field(
        ...,
        description="Associated MITRE ATT&CK Technique Name.",
    )
    confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score in the triage assessment (0.0 to 1.0).",
    )
    assessed_severity: AllowedSeverity = Field(
        ...,
        description="Assessed severity level based on evidence and impact.",
    )
    suggested_action: AllowedAction = Field(
        ...,
        description="Next containment action chosen strictly from the allowed action registry.",
    )
    investigation_steps: List[str] = Field(
        ...,
        min_length=1,
        description="Concrete, actionable checklist items for the SOC analyst.",
    )
    reasoning: str = Field(
        ...,
        description="Technical justification citing specific retrieved MITRE guidance and runbook SOP.",
    )
    retrieved_runbook: str = Field(
        ...,
        description="Name of the grounded runbook referenced for this assessment.",
    )
    source: str = Field(
        default="ollama",
        description="Inference provider: 'ollama' for live local model, 'offline_fallback' for deterministic engine.",
    )
