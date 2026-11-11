"""Tests for Milestone 5 Evaluation Suite (hallucination checker + runner)."""

import pytest

from llm.schemas import TriageReport
from evals.hallucination_checker import (
    HallucinationChecker,
    EvalCase,
    EvalRunner,
    KNOWN_MITRE_IDS,
)
from guardrails.policy import ALLOWED_ACTIONS


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _report(**overrides) -> TriageReport:
    base = dict(
        alert_id="eval-test-001",
        incident_summary="Benign test incident.",
        mitre_technique_id="T1190",
        mitre_technique_name="Exploit Public-Facing Application",
        confidence_score=0.85,
        assessed_severity="HIGH",
        suggested_action="notify_analyst",
        investigation_steps=["Check logs", "Isolate host"],
        reasoning="SQLi detected.",
        retrieved_runbook="SQLi IR",
    )
    base.update(overrides)
    return TriageReport.model_construct(**base)


# ---------------------------------------------------------------------------
# HallucinationChecker unit tests
# ---------------------------------------------------------------------------

class TestHallucinationChecker:
    def setup_method(self):
        self.checker = HallucinationChecker()

    def test_valid_report_passes_all_checks(self):
        result = self.checker.check(_report())
        assert result.passed is True
        assert result.issues == []

    def test_hallucination_checker_catches_fake_mitre_id(self):
        """A MITRE ID not in the knowledge base must be flagged."""
        bad = _report(mitre_technique_id="T9999")
        result = self.checker.check(bad)
        assert result.passed is False
        assert any("T9999" in issue for issue in result.issues)

    def test_catches_invalid_action(self):
        """An action not in the allow-list must be flagged."""
        bad = _report(suggested_action="delete_all_logs")
        result = self.checker.check(bad)
        assert result.passed is False
        assert any("delete_all_logs" in issue for issue in result.issues)

    def test_catches_empty_investigation_steps(self):
        """Empty investigation_steps list must be flagged."""
        bad = _report(investigation_steps=[])
        result = self.checker.check(bad)
        assert result.passed is False
        assert any("empty" in issue.lower() for issue in result.issues)

    def test_catches_confidence_out_of_range(self):
        """confidence_score > 1.0 must be flagged."""
        bad = _report(confidence_score=1.5)
        result = self.checker.check(bad)
        assert result.passed is False
        assert any("1.5" in issue for issue in result.issues)

    def test_catches_negative_confidence(self):
        """confidence_score < 0.0 must be flagged."""
        bad = _report(confidence_score=-0.1)
        result = self.checker.check(bad)
        assert result.passed is False

    def test_all_known_mitre_ids_pass(self):
        """Every ID in KNOWN_MITRE_IDS should not trigger the MITRE check."""
        for mid in KNOWN_MITRE_IDS:
            report = _report(mitre_technique_id=mid)
            result = self.checker.check(report)
            mitre_issues = [i for i in result.issues if "MITRE" in i]
            assert mitre_issues == [], f"ID {mid} falsely flagged"


# ---------------------------------------------------------------------------
# EvalRunner tests
# ---------------------------------------------------------------------------

class TestEvalRunner:
    def _make_case(self, expects_hallucination: bool, **report_kwargs) -> EvalCase:
        return EvalCase(
            case_id="tc-test",
            report=_report(**report_kwargs),
            expects_hallucination=expects_hallucination,
            description="test case",
        )

    def test_eval_runner_pass_rate_clean(self):
        """All-clean cases should yield 100% pass rate."""
        runner = EvalRunner()
        cases = [self._make_case(False) for _ in range(5)]
        result = runner.run(cases)
        assert result.pass_rate == 1.0
        assert result.hallucination_rate == 0.0

    def test_eval_runner_detects_expected_hallucination(self):
        """Cases expecting hallucination with injected bad data pass."""
        runner = EvalRunner()
        cases = [
            self._make_case(True, mitre_technique_id="T9999"),
            self._make_case(True, suggested_action="delete_all_logs"),
            self._make_case(True, confidence_score=99.0),
        ]
        result = runner.run(cases)
        assert result.passed == 3

    def test_eval_runner_mixed_cases(self):
        """Mix of clean and hallucination cases reported correctly."""
        runner = EvalRunner()
        cases = [
            self._make_case(False),                             # clean, expected pass
            self._make_case(True, mitre_technique_id="T0000"),  # hallucination, expected pass
            self._make_case(False, mitre_technique_id="T8888"), # hallucination, NOT expected -> fail
        ]
        result = runner.run(cases)
        assert result.total == 3
        assert result.passed == 2  # first two pass; third fails

    def test_eval_runner_hallucination_rate_metric(self):
        """Hallucination rate should equal fraction of unintended hallucinations."""
        runner = EvalRunner()
        # 2 clean cases, 1 accidentally hallucinates
        cases = [
            self._make_case(False),
            self._make_case(False),
            self._make_case(False, mitre_technique_id="T9999"),  # unexpected hallucination
        ]
        result = runner.run(cases)
        # 1 out of 3 clean cases hallucinated
        assert abs(result.hallucination_rate - 1 / 3) < 1e-9
