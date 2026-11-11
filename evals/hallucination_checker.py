"""Hallucination Checker & Evaluation Runner.

Lightweight Python-native replacement for a Promptfoo / LLM-as-judge
eval suite.  Checks triage reports for structural hallucinations (fake
MITRE IDs, invalid actions, etc.) and runs a fixed annotated test set.

Usage (CLI)::

    py evals/run_evals.py
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from llm.schemas import AllowedAction, TriageReport
from guardrails.policy import ALLOWED_ACTIONS

# ---------------------------------------------------------------------------
# Known MITRE ATT&CK technique IDs (must stay in sync with knowledge_base).
# ---------------------------------------------------------------------------
KNOWN_MITRE_IDS: frozenset[str] = frozenset(
    {
        "T1190",  # Exploit Public-Facing Application
        "T1110",  # Brute Force
        "T1083",  # File and Directory Discovery
        "T1059",  # Command and Scripting Interpreter
        "T1046",  # Network Service Discovery
        "T1078",  # Valid Accounts
        "T1133",  # External Remote Services
        # Accept parent technique IDs (T1059.001 etc.)
        "T1059.001",
        "T1059.003",
        "T1059.004",
        "T1059.006",
        "T1059.007",
        "T1110.001",
        "T1110.003",
        "T1110.004",
    }
)


@dataclass
class HallucinationResult:
    """Result of a single hallucination check.

    Attributes:
        passed: True iff no hallucinations were detected.
        issues: List of human-readable issue descriptions.
    """

    passed: bool = True
    issues: list[str] = field(default_factory=list)

    def flag(self, reason: str) -> None:
        """Record a hallucination issue and mark the result as failed."""
        self.passed = False
        self.issues.append(reason)


class HallucinationChecker:
    """Inspect :class:`~llm.schemas.TriageReport` objects for hallucinations.

    Checks performed:

    1. MITRE technique ID must be in :data:`KNOWN_MITRE_IDS`.
    2. ``suggested_action`` must be in the allow-list.
    3. ``investigation_steps`` must have at least one entry.
    4. ``confidence_score`` must be in ``[0.0, 1.0]``.
    """

    def check(self, report: TriageReport) -> HallucinationResult:
        """Run all hallucination checks on *report*.

        Args:
            report: Triage report to validate.

        Returns:
            A :class:`HallucinationResult` describing any issues found.
        """
        result = HallucinationResult()

        # 1. MITRE ID
        mid = report.mitre_technique_id.strip()
        if mid not in KNOWN_MITRE_IDS:
            result.flag(
                f"Unknown MITRE technique ID '{mid}' "
                f"(not in knowledge base)."
            )

        # 2. Action allow-list
        if report.suggested_action not in ALLOWED_ACTIONS:
            result.flag(
                f"Unauthorized action '{report.suggested_action}' "
                f"(not in allow-list)."
            )

        # 3. Investigation steps
        if not report.investigation_steps:
            result.flag("investigation_steps list is empty.")

        # 4. Confidence range
        if not (0.0 <= report.confidence_score <= 1.0):
            result.flag(
                f"confidence_score {report.confidence_score} out of [0, 1]."
            )

        return result


@dataclass
class EvalCase:
    """A single evaluation test case.

    Attributes:
        case_id: Identifier from ``test_cases.json``.
        report: The triage report under test.
        expects_hallucination: True iff the case is expected to fail.
        description: Human-readable label.
    """

    case_id: str
    report: TriageReport
    expects_hallucination: bool
    description: str


@dataclass
class EvalResult:
    """Aggregated result of an evaluation run.

    Attributes:
        total: Total number of cases.
        passed: Number of cases that behaved as expected.
        hallucination_rate: Fraction of non-hallucination cases that
            produced at least one hallucination flag.
        details: Per-case details list.
    """

    total: int = 0
    passed: int = 0
    hallucination_rate: float = 0.0
    details: list[dict[str, Any]] = field(default_factory=list)

    @property
    def pass_rate(self) -> float:
        """Overall pass rate across all cases."""
        return self.passed / self.total if self.total else 0.0


class EvalRunner:
    """Run a list of :class:`EvalCase` objects and collect metrics.

    Args:
        checker: :class:`HallucinationChecker` instance to use.
    """

    def __init__(self, checker: Optional[HallucinationChecker] = None) -> None:
        self._checker = checker or HallucinationChecker()

    def run(self, cases: list[EvalCase]) -> EvalResult:
        """Execute all *cases* and return aggregated :class:`EvalResult`.

        A case *passes* when:

        - ``expects_hallucination=True`` and at least one hallucination
          was detected, **or**
        - ``expects_hallucination=False`` and no hallucinations were
          detected.

        Args:
            cases: Evaluation cases to run.

        Returns:
            :class:`EvalResult` with per-case details and summary metrics.
        """
        result = EvalResult(total=len(cases))
        clean_total = 0
        clean_hallucinated = 0

        for case in cases:
            hr = self._checker.check(case.report)
            detected = not hr.passed

            if case.expects_hallucination:
                # We want the checker to flag something.
                ok = detected
            else:
                # We want clean output.
                ok = not detected
                clean_total += 1
                if detected:
                    clean_hallucinated += 1

            if ok:
                result.passed += 1

            result.details.append(
                {
                    "case_id": case.case_id,
                    "description": case.description,
                    "passed": ok,
                    "expects_hallucination": case.expects_hallucination,
                    "issues": hr.issues,
                }
            )

        result.hallucination_rate = (
            clean_hallucinated / clean_total if clean_total else 0.0
        )
        return result
