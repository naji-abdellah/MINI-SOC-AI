"""Triage Pipeline Coordinator for MiniSOC-AI.

Pairs incoming security alerts with retrieved MITRE and runbook intelligence,
formats prompt injection-hardened instructions, executes LLM triage, then
enforces policy, submits to the approval gate, and appends to the audit log.
"""

import os
from typing import Any, Dict, List, Optional, Tuple

from llm.schemas import TriageReport
from llm.rag.retriever import KnowledgeRetriever
from llm.prompts import build_hardened_triage_prompt, build_naive_triage_prompt
from llm.client import OllamaClient
from guardrails.policy import PolicyEnforcer
from guardrails.approval import ApprovalGate, ApprovalRequest
from guardrails.audit_log import AuditLog


class TriageCoordinator:
    """Coordinates RAG retrieval, prompt quarantine, LLM triage, and guardrails.

    Pipeline order per alert:

    1. RAG retrieval
    2. Prompt assembly (hardened or naive)
    3. LLM generation
    4. Policy enforcement (action sanitization)
    5. Approval gate submission
    6. Audit log append (triage + approval entries)
    """

    def __init__(
        self,
        retriever: Optional[KnowledgeRetriever] = None,
        llm_client: Optional[OllamaClient] = None,
        policy: Optional[PolicyEnforcer] = None,
        approval_gate: Optional[ApprovalGate] = None,
        audit_log: Optional[AuditLog] = None,
    ):
        self.retriever = retriever or KnowledgeRetriever()
        self.client = llm_client or OllamaClient()
        self.policy = policy or PolicyEnforcer()
        self.approval_gate = approval_gate or ApprovalGate(
            db_path=os.getenv("MINISOC_DB", "data/minisoc.duckdb")
        )
        self.audit_log = audit_log or AuditLog()

    def triage_alert(
        self,
        alert_data: Dict[str, Any],
        use_naive_prompt: bool = False,
    ) -> TriageReport:
        """Execute end-to-end RAG-grounded triage on a single alert.

        Steps:
            1. RAG retrieval
            2. Prompt assembly
            3. LLM generation
            4. Policy enforcement
            5. Approval gate submission
            6. Audit log append

        Args:
            alert_data: Raw alert dict (must contain at least
                ``alert_id`` and optionally ``mitre_technique_id``).
            use_naive_prompt: When True, skips XML quarantine tags
                (used in break-it prompt injection tests).

        Returns:
            Policy-sanitized :class:`~llm.schemas.TriageReport`.
        """
        technique_id = alert_data.get("mitre_technique_id", "T1190")
        alert_id = alert_data.get("alert_id", "unknown-alert")

        # 1. RAG Retrieval
        rag_context = self.retriever.retrieve(technique_id=technique_id)

        # 2. Prompt Assembly
        if use_naive_prompt:
            prompt = build_naive_triage_prompt(alert_data, rag_context)
        else:
            prompt = build_hardened_triage_prompt(alert_data, rag_context)

        # 3. LLM Generation
        report = self.client.generate_triage(
            prompt, alert_id=alert_id, is_naive=use_naive_prompt
        )

        # 4. Policy Enforcement — sanitize unauthorized actions
        report = self.policy.sanitize_report(report)

        # 5. Approval Gate — create pending approval request
        approval_req = self.approval_gate.submit(report)

        # 6. Audit Log — record triage event then approval submission
        self.audit_log.append(
            "triage",
            {
                "alert_id": alert_id,
                "report": report.model_dump(),
            },
        )
        self.audit_log.append(
            "approval",
            {
                "request_id": approval_req.request_id,
                "alert_id": alert_id,
                "status": approval_req.status,
                "suggested_action": approval_req.suggested_action,
            },
        )

        return report

    def batch_triage(self, alerts: List[Dict[str, Any]]) -> List[TriageReport]:
        """Triage a list of alerts in sequence.

        Args:
            alerts: List of raw alert dicts.

        Returns:
            List of policy-sanitized :class:`~llm.schemas.TriageReport`.
        """
        reports = []
        for a in alerts:
            report = self.triage_alert(a)
            reports.append(report)
        return reports
