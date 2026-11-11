"""MiniSOC-AI LLM Triage CLI.

Reads active alerts from DuckDB, enriches with RAG context, and runs local LLM triage.

Usage:
    python -m llm.cli --db data/minisoc.duckdb --limit 3
"""

import argparse
import json
import sys
from pathlib import Path
import duckdb

from llm.triage import TriageCoordinator


def main():
    parser = argparse.ArgumentParser(description="MiniSOC-AI Local LLM Triage CLI")
    parser.add_argument("--db", default="data/minisoc.duckdb", help="Path to DuckDB database file")
    parser.add_argument("--limit", type=int, default=3, help="Maximum number of alerts to triage")
    parser.add_argument("--offline", action="store_true", help="Force offline deterministic evaluation")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"[!] Database not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    conn = duckdb.connect(database=args.db)
    cursor = conn.cursor()

    # Check if alerts table exists
    tables = [r[0] for r in cursor.execute("SHOW TABLES;").fetchall()]
    if "alerts" not in tables:
        print("[!] No 'alerts' table found. Run 'python -m detections.cli' first to generate alerts.")
        sys.exit(1)

    rel = cursor.execute("""
        SELECT * FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?;
    """, [args.limit])
    cols = [desc[0] for desc in rel.description]
    alerts = [dict(zip(cols, r)) for r in rel.fetchall()]
    cursor.close()
    conn.close()

    if not alerts:
        print("[*] No alerts currently pending in queue.")
        return

    print(f"[*] Triaging {len(alerts)} alerts with Local LLM + RAG...\n")
    coordinator = TriageCoordinator()

    for idx, alert in enumerate(alerts, 1):
        report = coordinator.triage_alert(alert)

        print("=" * 65)
        print(f"[AI TRIAGE REPORT #{idx}] Alert ID: {report.alert_id[:12]}...")
        print("=" * 65)
        print(f"Summary:       {report.incident_summary}")
        print(f"MITRE ATT&CK:  {report.mitre_technique_id} - {report.mitre_technique_name}")
        print(f"Assessed Sev:  {report.assessed_severity} (Confidence: {report.confidence_score*100:.0f}%)")
        print(f"Action:        >>> {report.suggested_action.upper()} <<<")
        print(f"Runbook:       {report.retrieved_runbook}")
        print("\nAnalyst Investigation Checklist:")
        for step in report.investigation_steps:
            print(f"  [ ] {step}")
        print(f"\nReasoning:     {report.reasoning}")
        print("-" * 65 + "\n")


if __name__ == "__main__":
    main()
