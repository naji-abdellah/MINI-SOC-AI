"""Tests for Milestone 5 Guardrails: Policy Enforcer and Approval Gate."""

import pytest

from llm.schemas import TriageReport
from guardrails.policy import PolicyEnforcer, ALLOWED_ACTIONS, SAFE_FALLBACK_ACTION
from guardrails.approval import ApprovalGate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(**overrides) -> TriageReport:
    """Return a minimal valid TriageReport, optionally patching fields."""
    defaults = dict(
        alert_id="alert-test-001",
        incident_summary="Test incident.",
        mitre_technique_id="T1190",
        mitre_technique_name="Exploit Public-Facing Application",
        confidence_score=0.9,
        assessed_severity="HIGH",
        suggested_action="block_ip",
        investigation_steps=["Step 1: Isolate", "Step 2: Investigate"],
        reasoning="SQLi pattern detected.",
        retrieved_runbook="SQLi Incident Response",
    )
    defaults.update(overrides)
    return TriageReport(**defaults)


# ---------------------------------------------------------------------------
# PolicyEnforcer tests
# ---------------------------------------------------------------------------

class TestPolicyEnforcer:
    def test_all_allowed_actions_validate(self):
        """Every value in ALLOWED_ACTIONS should pass validate_action."""
        enforcer = PolicyEnforcer()
        for action in ALLOWED_ACTIONS:
            assert enforcer.validate_action(action), f"Expected {action} to be allowed"

    def test_unknown_action_rejected(self):
        """An action not in the registry must be rejected."""
        enforcer = PolicyEnforcer()
        assert not enforcer.validate_action("delete_all_logs")
        assert not enforcer.validate_action("rm -rf /")
        assert not enforcer.validate_action("")

    def test_policy_allow_list_enforcement(self):
        """Unauthorized action in a report gets sanitized to notify_analyst."""
        enforcer = PolicyEnforcer()
        # Inject a forbidden action using model_construct (bypasses Pydantic
        # validation so we can represent the bad state that an LLM might emit).
        bad_report = TriageReport.model_construct(
            **_make_report().model_dump() | {"suggested_action": "wipe_database"}
        )
        sanitized = enforcer.sanitize_report(bad_report)
        assert sanitized.suggested_action == SAFE_FALLBACK_ACTION
        assert "wipe_database" in sanitized.reasoning

    def test_policy_severity_floor_and_dismissal_override(self):
        """HIGH/CRITICAL alerts cannot have their severity downgraded to LOW or action set to dismiss_alert."""
        enforcer = PolicyEnforcer()
        downgraded_report = TriageReport.model_construct(
            **_make_report().model_dump() | {
                "assessed_severity": "LOW",
                "suggested_action": "dismiss_alert",
            }
        )
        sanitized = enforcer.sanitize_report(downgraded_report, rule_severity="HIGH")
        assert sanitized.suggested_action == "notify_analyst", "dismiss_alert must be overridden on HIGH rule"
        assert sanitized.assessed_severity == "MEDIUM", "LOW severity must be raised to floor MEDIUM"
        assert "[POLICY OVERRIDE]" in sanitized.reasoning

    def test_valid_action_not_mutated(self):
        """A report with a valid action must be returned unchanged."""
        enforcer = PolicyEnforcer()
        report = _make_report(suggested_action="isolate_host")
        result = enforcer.sanitize_report(report)
        assert result.suggested_action == "isolate_host"
        assert result.reasoning == report.reasoning  # unchanged

    def test_policy_enforcer_allows_all_literal_values(self):
        """Every AllowedAction Literal value passes sanitization unchanged."""
        enforcer = PolicyEnforcer()
        for action in ALLOWED_ACTIONS:
            report = _make_report(suggested_action=action)
            result = enforcer.sanitize_report(report)
            assert result.suggested_action == action


# ---------------------------------------------------------------------------
# ApprovalGate tests
# ---------------------------------------------------------------------------

class TestApprovalGate:
    def _gate(self) -> ApprovalGate:
        return ApprovalGate(db_path=":memory:")

    def test_approval_gate_submit_creates_pending_request(self):
        """Submitting a triage report produces a pending ApprovalRequest."""
        gate = self._gate()
        report = _make_report()
        req = gate.submit(report)
        assert req.status == "pending"
        assert req.alert_id == report.alert_id
        assert req.suggested_action == report.suggested_action

    def test_approval_gate_lifecycle(self):
        """Submit -> approve flow transitions status correctly."""
        gate = self._gate()
        report = _make_report()
        req = gate.submit(report)
        assert req.status == "pending"

        approved = gate.approve(req.request_id, analyst="alice")
        assert approved.status == "approved"
        assert approved.analyst == "alice"

        # Attempting to re-approve or reject an already approved request must raise ValueError
        with pytest.raises(ValueError):
            gate.approve(req.request_id, analyst="alice")
        with pytest.raises(ValueError):
            gate.reject(req.request_id, analyst="bob")

    def test_approval_gate_rejection(self):
        """Submit -> reject stores reason in analyst_notes."""
        gate = self._gate()
        req = gate.submit(_make_report())
        rejected = gate.reject(req.request_id, analyst="bob", reason="False positive")
        assert rejected.status == "rejected"
        assert rejected.analyst == "bob"
        assert "False positive" in rejected.analyst_notes

    def test_approval_gate_get_roundtrip(self):
        """Fetching by request_id returns the same record."""
        gate = self._gate()
        req = gate.submit(_make_report(alert_id="roundtrip-01"))
        fetched = gate.get(req.request_id)
        assert fetched.request_id == req.request_id
        assert fetched.alert_id == "roundtrip-01"

    def test_approval_gate_missing_request_raises(self):
        """Fetching a non-existent ID must raise KeyError."""
        gate = self._gate()
        with pytest.raises(KeyError):
            gate.get("does-not-exist")
