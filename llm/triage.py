"""Triage Pipeline Coordinator for MiniSOC-AI.

Pairs incoming security alerts with retrieved MITRE and runbook intelligence,
formats prompt injection-hardened instructions, and executes LLM triage.
"""

from typing import Any, Dict, List, Optional
from llm.schemas import TriageReport
from llm.rag.retriever import KnowledgeRetriever
from llm.prompts import build_hardened_triage_prompt, build_naive_triage_prompt
from llm.client import OllamaClient


class TriageCoordinator:
    """Coordinates RAG retrieval, prompt quarantine, and LLM triage execution."""

    def __init__(
        self,
        retriever: Optional[KnowledgeRetriever] = None,
        llm_client: Optional[OllamaClient] = None,
    ):
        self.retriever = retriever or KnowledgeRetriever()
        self.client = llm_client or OllamaClient()

    def triage_alert(self, alert_data: Dict[str, Any], use_naive_prompt: bool = False) -> TriageReport:
        """Execute end-to-end RAG-grounded triage on a single alert."""
        technique_id = alert_data.get("mitre_technique_id", "T1190")
        alert_id = alert_data.get("alert_id", "unknown-alert")

        # 1. RAG Retrieval
        rag_context = self.retriever.retrieve(technique_id=technique_id)

        # 2. Prompt Assembly (Hardened vs Naive for testing)
        if use_naive_prompt:
            prompt = build_naive_triage_prompt(alert_data, rag_context)
        else:
            prompt = build_hardened_triage_prompt(alert_data, rag_context)

        # 3. LLM Generation
        report = self.client.generate_triage(prompt, alert_id=alert_id, is_naive=use_naive_prompt)
        return report

    def batch_triage(self, alerts: List[Dict[str, Any]]) -> List[TriageReport]:
        """Triage a list of alerts in sequence."""
        reports = []
        for a in alerts:
            report = self.triage_alert(a)
            reports.append(report)
        return reports
