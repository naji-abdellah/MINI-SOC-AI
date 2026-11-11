"""CLI entry point for the MiniSOC-AI evaluation suite.

Loads test cases from ``evals/test_cases.json``, runs them through
the :class:`~evals.hallucination_checker.EvalRunner`, and prints a
summary report.

Usage::

    py evals/run_evals.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from evals.hallucination_checker import (
    EvalCase,
    EvalRunner,
    HallucinationChecker,
)
from llm.schemas import TriageReport
from llm.triage import TriageCoordinator

_TEST_CASES_PATH = Path(__file__).parent / "test_cases.json"


def _make_report(alert: dict, overrides: dict | None = None) -> TriageReport:
    """Generate a triage report for *alert*, optionally patching fields."""
    coordinator = TriageCoordinator()
    report = coordinator.triage_alert(alert)
    if overrides:
        data = report.model_dump()
        data.update(overrides)
        # Pydantic may reject invalid values in strict mode; use
        # model_construct to bypass validation for hallucination injection.
        report = TriageReport.model_construct(**data)
    return report


def _load_cases() -> list[EvalCase]:
    raw = json.loads(_TEST_CASES_PATH.read_text(encoding="utf-8"))
    cases: list[EvalCase] = []
    for tc in raw:
        overrides = tc.get("inject_hallucination")
        expects = tc.get("expected", {}).get("hallucination_detected", False)
        report = _make_report(tc["alert"], overrides)
        cases.append(
            EvalCase(
                case_id=tc["id"],
                report=report,
                expects_hallucination=bool(expects),
                description=tc["description"],
            )
        )
    return cases


def main() -> None:
    print("MiniSOC-AI Evaluation Suite")
    print("=" * 50)

    cases = _load_cases()
    runner = EvalRunner(HallucinationChecker())
    result = runner.run(cases)

    # Per-case detail.
    for d in result.details:
        status = "PASS" if d["passed"] else "FAIL"
        print(f"  [{status}] {d['case_id']} - {d['description']}")
        for issue in d["issues"]:
            print(f"         ISSUE: {issue}")

    print()
    print(f"Results: {result.passed}/{result.total} passed")
    print(f"Pass rate:          {result.pass_rate:.1%}")
    print(f"Hallucination rate: {result.hallucination_rate:.1%}")

    sys.exit(0 if result.pass_rate >= 0.8 else 1)


if __name__ == "__main__":
    main()
