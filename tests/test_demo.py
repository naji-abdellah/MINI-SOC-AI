"""Unit tests for the 1-Command Demo Runner & Attack Simulator (scripts/demo.py)."""

from pathlib import Path
import pytest
from scripts.demo import generate_attack_scenarios, run_pipeline


def test_generate_attack_scenarios():
    scenarios = ["all", "recon", "sqli", "bruteforce", "cmdi", "lfi"]
    for s in scenarios:
        lines = generate_attack_scenarios(s)
        assert len(lines) > 0
        assert all(isinstance(line, str) for line in lines)

    # All should be a superset
    all_lines = generate_attack_scenarios("all")
    assert len(all_lines) >= 10


def test_demo_pipeline_end_to_end(tmp_path):
    test_db = str(tmp_path / "demo_test.duckdb")
    test_audit = str(tmp_path / "demo_audit.jsonl")

    summary = run_pipeline(
        scenario="all",
        db_path=test_db,
        audit_path=test_audit,
        launch_dashboard=False,
    )

    assert summary["events_simulated"] >= 10
    assert summary["threat_intel_matches"] > 0
    assert summary["rules_evaluated"] >= 8
    assert summary["alerts_generated"] > 0
    assert summary["alerts_triaged"] > 0
    assert summary["audit_chain_valid"] is True
