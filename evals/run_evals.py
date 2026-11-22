"""CLI entry point for the MiniSOC-AI evaluation suite.

Loads test cases from ``evals/test_cases.json``, evaluates triage reports
for both structural safety and semantic correctness against expected ground truth,
and prints a detailed evaluation summary.

Usage::

    py evals/run_evals.py
"""

from __future__ import annotations

import json
import sys
import tempfile
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
from guardrails.approval import ApprovalGate
from guardrails.audit_log import AuditLog

_TEST_CASES_PATH = Path(__file__).parent / "test_cases.json"


def _make_report(
    alert: dict,
    coordinator: TriageCoordinator,
    overrides: dict | None = None,
) -> TriageReport:
    """Generate a triage report for *alert*, optionally patching fields."""
    report = coordinator.triage_alert(alert)
    if overrides:
        data = report.model_dump()
        data.update(overrides)
        # model_construct bypasses Pydantic strict validation to simulate model hallucinations
        report = TriageReport.model_construct(**data)
    return report


def _load_cases() -> list[EvalCase]:
    raw = json.loads(_TEST_CASES_PATH.read_text(encoding="utf-8"))
    cases: list[EvalCase] = []

    # Use a temporary isolated directory for evals to prevent production log pollution
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_db = str(Path(tmp_dir) / "eval_temp.duckdb")
        tmp_audit = str(Path(tmp_dir) / "eval_audit.jsonl")

        gate = ApprovalGate(db_path=tmp_db)
        audit = AuditLog(log_path=tmp_audit)
        coordinator = TriageCoordinator(approval_gate=gate, audit_log=audit)

        for tc in raw:
            overrides = tc.get("inject_hallucination")
            expects = tc.get("expected", {}).get("hallucination_detected", False)
            expected_dict = tc.get("expected")
            report = _make_report(tc["alert"], coordinator, overrides)
            cases.append(
                EvalCase(
                    case_id=tc["id"],
                    report=report,
                    expects_hallucination=bool(expects),
                    description=tc["description"],
                    expected=expected_dict,
                )
            )

    return cases


def main() -> None:
    print("MiniSOC-AI Evaluation & Correctness Suite")
    print("=" * 60)

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
