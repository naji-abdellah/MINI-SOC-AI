"""RAG Retrieval Engine for MiniSOC-AI.

Provides high-speed, lightweight in-memory retrieval of MITRE ATT&CK technique guidance
and SOC standard operating runbooks without heavyweight external database daemons.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RAGContext(BaseModel):
    """Retrieved security intelligence context for alert triage."""
    mitre_technique_id: str
    mitre_technique_name: str
    mitre_description: str
    mitre_detection_guidance: str
    mitre_mitigation: str
    runbook_name: str
    recommended_actions: List[str] = Field(default_factory=list)
    allowed_containment_actions: List[str] = Field(default_factory=list)

    def to_prompt_context(self) -> str:
        """Format retrieved context for LLM prompt grounding."""
        actions_bullet = "\n".join(f"  - {a}" for a in self.recommended_actions)
        return (
            f"=== MITRE ATT&CK Context ===\n"
            f"Technique: {self.mitre_technique_id} ({self.mitre_technique_name})\n"
            f"Description: {self.mitre_description}\n"
            f"Detection Guidance: {self.mitre_detection_guidance}\n"
            f"Mitigation: {self.mitre_mitigation}\n\n"
            f"=== SOC Runbook: {self.runbook_name} ===\n"
            f"Standard Operating Procedures:\n{actions_bullet}\n"
            f"Permitted Containment Actions: {', '.join(self.allowed_containment_actions)}\n"
        )


class KnowledgeRetriever:
    """In-memory RAG retriever for MITRE ATT&CK and SOC runbooks."""

    def __init__(self, kb_dir: str = "llm/rag/knowledge_base"):
        self.kb_path = Path(kb_dir)
        self.mitre_db: Dict[str, dict] = {}
        self.runbooks: List[dict] = []
        self._load_knowledge()

    def _load_knowledge(self):
        """Load JSON knowledge bases."""
        mitre_file = self.kb_path / "mitre_attack.json"
        if mitre_file.exists():
            with open(mitre_file, "r", encoding="utf-8") as f:
                entries = json.load(f)
                for item in entries:
                    self.mitre_db[item["id"].upper()] = item

        runbook_file = self.kb_path / "soc_runbooks.json"
        if runbook_file.exists():
            with open(runbook_file, "r", encoding="utf-8") as f:
                self.runbooks = json.load(f)

    def retrieve(self, technique_id: str, query_hint: Optional[str] = None) -> RAGContext:
        """Retrieve matching MITRE technique context and associated incident runbook."""
        clean_tid = technique_id.upper().strip()

        # Retrieve MITRE entry (or fallback)
        mitre_entry = self.mitre_db.get(clean_tid)
        if not mitre_entry:
            # Fallback for generic or unknown technique
            mitre_entry = {
                "id": clean_tid,
                "name": "General Security Incident",
                "description": "Suspicious anomalous activity detected by SOC pipeline.",
                "detection": "Investigate correlated events, check firewall logs, inspect payload.",
                "mitigation": "Block offending source IP and investigate host integrity.",
            }

        # Find matching runbook
        matched_runbook = None
        for rb in self.runbooks:
            if clean_tid in rb.get("applicable_techniques", []):
                matched_runbook = rb
                break

        # Fallback runbook if no exact technique match
        if not matched_runbook:
            matched_runbook = {
                "name": "Standard Security Incident Triage Runbook",
                "immediate_actions": [
                    "Inspect raw event payload for signs of malicious intent.",
                    "Verify source IP reputation and geographical origin.",
                    "Determine if requests received successful (HTTP 200) responses.",
                    "Notify analyst if repeated high-severity indicators are present."
                ],
                "containment_options": ["notify_analyst", "block_ip", "dismiss_alert"],
            }

        return RAGContext(
            mitre_technique_id=mitre_entry["id"],
            mitre_technique_name=mitre_entry["name"],
            mitre_description=mitre_entry["description"],
            mitre_detection_guidance=mitre_entry["detection"],
            mitre_mitigation=mitre_entry["mitigation"],
            runbook_name=matched_runbook["name"],
            recommended_actions=matched_runbook["immediate_actions"],
            allowed_containment_actions=matched_runbook["containment_options"],
        )
