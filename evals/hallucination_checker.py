"""Hallucination Checker & Correctness Evaluation Runner.

Evaluates triage reports against:
1. Structural integrity: Valid MITRE technique ID from Knowledge Base, authorized action,
   non-empty investigation steps, valid confidence range.
2. Semantic correctness: Ensures the LLM correctly infers the expected technique ID,
   recommends the appropriate containment action, and meets confidence thresholds.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
from typing import Any, Optional

from llm.schemas import AllowedAction, TriageReport
from guardrails.policy import ALLOWED_ACTIONS


def _load_known_mitre_ids() -> frozenset[str]:
    """Derive known MITRE IDs strictly from the knowledge base without artificial parent IDs."""
    kb_path = Path(__file__).parent.parent / "llm" / "rag" / "knowledge_base" / "mitre_attack.json"
    ids = set()
    if kb_path.exists():
        try:
            data = json.loads(kb_path.read_text(encoding="utf-8"))
            for item in data:
                mid = item.get("id")
                if mid:
                    ids.add(mid)
        except Exception:
            pass
    # Fallback to standard base set if KB not found
    if not ids:
        ids = {"T1190", "T1083", "T1110.001", "T1059", "T1595.002", "T1078", "T1003"}
    return frozenset(ids)


def _load_known_runbooks() -> dict[str, list[str]]:
    """Derive valid runbook names and their containment options from the knowledge base."""
    rb_path = Path(__file__).parent.parent / "llm" / "rag" / "knowledge_base" / "soc_runbooks.json"
    runbooks = {}
    if rb_path.exists():
        try:
            data = json.loads(rb_path.read_text(encoding="utf-8"))
            for item in data:
                name = item.get("name")
                opts = item.get("containment_options", [])
                if name:
                    runbooks[name] = opts
        except Exception:
            pass
    if not runbooks:
        runbooks = {
            "SQL Injection Incident Response Runbook": ["block_ip", "notify_analyst"],
            "Brute Force and Credential Spray Runbook": ["block_ip", "reset_credentials", "notify_analyst"],
            "Path Traversal and LFI Runbook": ["block_ip", "notify_analyst"],
            "OS Command Injection Critical Response Runbook": ["isolate_host", "block_ip", "notify_analyst"],
            "Automated Scanner and Reconnaissance Runbook": ["block_ip", "dismiss_alert", "notify_analyst"],
            "Compromised Account Response Runbook": ["isolate_host", "reset_credentials", "block_ip", "notify_analyst"],
        }
    return runbooks


KNOWN_MITRE_IDS: frozenset[str] = _load_known_mitre_ids()
KNOWN_RUNBOOKS: dict[str, list[str]] = _load_known_runbooks()


@dataclass
class HallucinationResult:
    """Result of a single evaluation check."""

    passed: bool = True
    issues: list[str] = field(default_factory=list)

    def flag(self, reason: str) -> None:
        """Record a failure/hallucination issue."""
        self.passed = False
        self.issues.append(reason)


class HallucinationChecker:
    """Inspects TriageReports for hallucinations and correctness against ground truth."""

    def check(
        self,
        report: TriageReport,
        expected: Optional[dict[str, Any]] = None,
    ) -> HallucinationResult:
        """Run structural and semantic correctness checks on *report*."""
        result = HallucinationResult()

        # 1. Structural MITRE ID check (must exist in KB)
        mid = report.mitre_technique_id.strip()
        if mid not in KNOWN_MITRE_IDS:
            result.flag(
                f"Unknown MITRE technique ID '{mid}' (not found in knowledge base)."
            )

        # 2. Action allow-list check
        if report.suggested_action not in ALLOWED_ACTIONS:
            result.flag(
                f"Unauthorized action '{report.suggested_action}' (not in allow-list)."
            )

        # 3. Investigation steps check
        if not report.investigation_steps:
            result.flag("investigation_steps list is empty.")

        # 4. Confidence range check
        if not (0.0 <= report.confidence_score <= 1.0):
            result.flag(
                f"confidence_score {report.confidence_score} out of [0, 1]."
            )

        # 5. Runbook validity and containment options check
        rb = report.retrieved_runbook.strip() if report.retrieved_runbook else ""
        if rb and rb not in KNOWN_RUNBOOKS:
            result.flag(
                f"Unknown runbook '{rb}' (not found in knowledge base)."
            )
        elif rb and report.suggested_action not in KNOWN_RUNBOOKS[rb]:
            result.flag(
                f"Action '{report.suggested_action}' is not permitted by runbook '{rb}' (permitted: {KNOWN_RUNBOOKS[rb]})."
            )

        # 6. Semantic Correctness Checks against ground truth (when expected is provided)
        if expected and not expected.get("hallucination_detected"):
            # Check expected technique ID
            exp_mid = expected.get("mitre_technique_id")
            if exp_mid:
                # Match exact or parent technique (e.g. T1110 matches T1110.001)
                mid_base = mid.split(".")[0]
                exp_base = exp_mid.split(".")[0]
                if mid != exp_mid and mid_base != exp_base:
                    result.flag(
                        f"Technique mismatch: got '{mid}', expected '{exp_mid}'"
                    )

            # Check expected containment action
            exp_act = expected.get("suggested_action")
            if exp_act and report.suggested_action != exp_act:
                result.flag(
                    f"Action mismatch: got '{report.suggested_action}', expected '{exp_act}'"
                )

            # Check minimum confidence
            min_conf = expected.get("min_confidence")
            if min_conf is not None and report.confidence_score < min_conf:
                result.flag(
                    f"Confidence {report.confidence_score} below minimum threshold {min_conf}"
                )

            # Check minimum investigation steps
            min_steps = expected.get("min_investigation_steps")
            if min_steps and len(report.investigation_steps) < min_steps:
                result.flag(
                    f"Investigation steps count {len(report.investigation_steps)} below minimum {min_steps}"
                )

        return result


@dataclass
class EvalCase:
    """A single evaluation test case."""

    case_id: str
    report: TriageReport
    expects_hallucination: bool
    description: str
    expected: Optional[dict[str, Any]] = None


@dataclass
class EvalResult:
    """Aggregated result of an evaluation run."""

    total: int = 0
    passed: int = 0
    hallucination_rate: float = 0.0
    details: list[dict[str, Any]] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        """Overall pass rate across all cases."""
        return self.passed / self.total if self.total else 0.0


class EvalRunner:
    """Run a list of :class:`EvalCase` objects and collect metrics."""

    def __init__(self, checker: Optional[HallucinationChecker] = None) -> None:
        self._checker = checker or HallucinationChecker()

    def run(self, cases: list[EvalCase]) -> EvalResult:
        """Execute all *cases* and return aggregated :class:`EvalResult`."""
        total = len(cases)
        passed = 0
        hallucination_count = 0
        details: list[dict[str, Any]] = []

        for case in cases:
            res = self._checker.check(case.report, expected=case.expected)

            if case.expects_hallucination:
                case_passed = not res.passed
            else:
                case_passed = res.passed
                if not res.passed:
                    hallucination_count += 1

            if case_passed:
                passed += 1

            details.append(
                {
                    "case_id": case.case_id,
                    "description": case.description,
                    "passed": case_passed,
                    "expects_hallucination": case.expects_hallucination,
                    "issues": res.issues,
                }
            )

        clean_denom = sum(1 for c in cases if not c.expects_hallucination)
        hrate = hallucination_count / clean_denom if clean_denom else 0.0

        return EvalResult(
            total=total,
            passed=passed,
            hallucination_rate=hrate,
            details=details,
        )
