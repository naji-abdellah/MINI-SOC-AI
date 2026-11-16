"""Local Threat Intelligence Enrichment Service for MiniSOC-AI.

Provides offline matching of incoming event attributes (such as source IPs)
against curated threat intelligence feeds (C2 infrastructure, Tor exit nodes,
and known scanner subnets) without external API dependencies or network latency.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from ingestion.schema import NormalizedEvent

_DEFAULT_TI_PATH = Path(__file__).parent.parent / "data" / "threat_intel" / "indicators.json"


class ThreatIntelIndicator(BaseModel):
    """A threat intelligence indicator with contextual metadata."""

    value: str = Field(..., description="IP address or domain indicator.")
    type: str = Field(default="ipv4", description="Indicator type: ipv4, domain, hash.")
    category: str = Field(..., description="Threat category: C2, TOR_EXIT, SCANNER, etc.")
    threat_actor: Optional[str] = Field(default=None, description="Attributed threat group or botnet.")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Confidence score.")
    description: str = Field(default="", description="Forensic description.")


class ThreatIntelService:
    """In-memory offline Threat Intelligence lookup engine."""

    def __init__(self, indicators_path: Optional[str | Path] = None):
        self._path = Path(indicators_path) if indicators_path else _DEFAULT_TI_PATH
        self._indicators: Dict[str, ThreatIntelIndicator] = {}
        self.reload()

    def reload(self) -> int:
        """Load indicators from disk. Returns count of loaded indicators."""
        self._indicators.clear()
        if not self._path.exists():
            return 0

        try:
            with open(self._path, "r", encoding="utf-8") as f:
                data = json.load(f)
            raw_list = data.get("indicators", [])
            for item in raw_list:
                ind = ThreatIntelIndicator(**item)
                self._indicators[ind.value.strip()] = ind
            return len(self._indicators)
        except Exception:
            return 0

    def lookup_ip(self, ip: Optional[str]) -> Optional[ThreatIntelIndicator]:
        """Check if an IP address exists in the local threat intelligence feed."""
        if not ip:
            return None
        return self._indicators.get(ip.strip())

    def enrich_event(self, event: NormalizedEvent) -> NormalizedEvent:
        """Enrich a NormalizedEvent in-place if its source IP matches a threat indicator.

        Adds tags like `ti:match`, `ti:category:<cat>`, and `ti:actor:<actor>`
        so detection rules and LLM triage can immediately leverage TI context.
        """
        match = self.lookup_ip(event.source_ip)
        if not match:
            return event

        tags = list(event.tags)
        tags.append("ti:match")
        tags.append(f"ti:category:{match.category}")
        if match.threat_actor:
            # clean tag string
            clean_actor = match.threat_actor.replace(" ", "_")
            tags.append(f"ti:actor:{clean_actor}")

        # Return updated event
        return event.model_copy(update={"tags": tags})

    @property
    def total_indicators(self) -> int:
        return len(self._indicators)
