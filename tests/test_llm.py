"""Unit tests for MiniSOC-AI Local LLM Triage and RAG Module."""

import pytest
from pydantic import ValidationError

from llm.schemas import TriageReport
from llm.rag.retriever import KnowledgeRetriever
from llm.prompts import build_hardened_triage_prompt
from llm.client import OllamaClient
from llm.triage import TriageCoordinator


def test_rag_retriever_mitre_and_runbook_lookup():
    """Verify knowledge retriever maps technique IDs to MITRE context and SOP runbooks."""
    retriever = KnowledgeRetriever()

    # Test T1190 (SQLi / Web exploit)
    ctx_sqli = retriever.retrieve("T1190")
    assert ctx_sqli.mitre_technique_id == "T1190"
    assert "Exploit Public-Facing Application" in ctx_sqli.mitre_technique_name
    assert "SQL Injection" in ctx_sqli.runbook_name
    assert "block_ip" in ctx_sqli.allowed_containment_actions

    # Test T1059 (Command Injection)
    ctx_cmdi = retriever.retrieve("T1059")
    assert ctx_cmdi.mitre_technique_id == "T1059"
    assert "isolate_host" in ctx_cmdi.allowed_containment_actions

    # Test T1110.001 (Brute Force)
    ctx_bf = retriever.retrieve("T1110.001")
    assert ctx_bf.mitre_technique_id == "T1110.001"
    assert "reset_credentials" in ctx_bf.allowed_containment_actions


def test_triage_report_schema_validation():
    """Verify TriageReport enforces allowed actions and severities."""
    valid_report = TriageReport(
        alert_id="alert-001",
        incident_summary="SQL injection attempt caught by web rule.",
        mitre_technique_id="T1190",
        mitre_technique_name="Exploit Public-Facing Application",
        confidence_score=0.95,
        assessed_severity="HIGH",
        suggested_action="block_ip",
        investigation_steps=["Check DB logs", "Block IP"],
        reasoning="Matched UNION SELECT in query parameters.",
        retrieved_runbook="SQL Injection Runbook",
    )
    assert valid_report.suggested_action == "block_ip"
    assert valid_report.assessed_severity == "HIGH"

    # Invalid action: must reject unauthorized commands (e.g. "hack_back" or "delete_database")
    with pytest.raises(ValidationError):
        TriageReport(
            alert_id="alert-002",
            incident_summary="Invalid test",
            mitre_technique_id="T1190",
            mitre_technique_name="Test",
            confidence_score=0.8,
            assessed_severity="HIGH",
            suggested_action="unauthorized_reboot_server",  # Not in allowed list
            investigation_steps=["step 1"],
            reasoning="test",
            retrieved_runbook="test",
        )


def test_hardened_prompt_encapsulation():
    """Verify prompt builder encapsulates raw log payloads inside untrusted XML boundaries."""
    retriever = KnowledgeRetriever()
    ctx = retriever.retrieve("T1190")

    alert = {
        "alert_id": "test-alert-1",
        "rule_title": "SQLi Probe",
        "severity": "HIGH",
        "source_ip": "10.0.0.99",
        "evidence": "GET /index.php?id=1' UNION SELECT 1--",
    }

    prompt = build_hardened_triage_prompt(alert, ctx)
    assert "<untrusted_event_evidence>" in prompt
    assert "</untrusted_event_evidence>" in prompt
    assert "GET /index.php?id=1' UNION SELECT 1--" in prompt


def test_triage_coordinator_end_to_end():
    """Verify end-to-end triage execution through the coordinator."""
    coordinator = TriageCoordinator()

    alert = {
        "alert_id": "alert-test-e2e",
        "rule_title": "OS Command Injection",
        "mitre_technique_id": "T1059",
        "severity": "CRITICAL",
        "source_ip": "10.0.0.50",
        "evidence": "POST /exec?cmd=;cat /etc/passwd",
    }

    report = coordinator.triage_alert(alert)
    assert isinstance(report, TriageReport)
    assert report.alert_id == "alert-test-e2e"
    assert report.mitre_technique_id == "T1059"
    assert report.assessed_severity == "CRITICAL"
    assert report.suggested_action == "isolate_host"
    assert len(report.investigation_steps) >= 1
