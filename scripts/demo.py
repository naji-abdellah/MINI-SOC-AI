"""MiniSOC-AI 1-Command End-to-End Demo Runner & Attack Simulator.

Simulates a multi-stage cyber attack campaign, runs real-time log ingestion
with threat intelligence enrichment, evaluates detection rules, triggers
AI triage with cryptographic audit logging, and launches the SOC analyst console.

Usage:
    py scripts/demo.py
    py scripts/demo.py --scenario sqli
    py scripts/demo.py --dashboard
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import os
from pathlib import Path
import subprocess
import sys
import time

# Allow running directly from repository root
sys.path.insert(0, str(Path(__file__).parent.parent))

import duckdb

from ingestion.dispatcher import parse_line
from ingestion.duckdb_store import DuckDBStore
from detections.engine import DetectionEngine
from llm.triage import TriageCoordinator
from guardrails.audit_log import AuditLog
from ml.active_learning import ActiveLearningLoop


def generate_attack_scenarios(scenario: str = "all") -> list[str]:
    """Generate realistic raw log lines for simulated attack scenarios."""
    scenarios = {
        "recon": [
            '198.51.100.4 - - [16/Nov/2026:08:00:01 +0000] "GET /.env HTTP/1.1" 404 150 "-" "Nikto/2.1.6"',
            '198.51.100.4 - - [16/Nov/2026:08:00:02 +0000] "GET /phpinfo.php HTTP/1.1" 404 150 "-" "Nikto/2.1.6"',
            '198.51.100.4 - - [16/Nov/2026:08:00:03 +0000] "GET /admin/config.php HTTP/1.1" 403 200 "-" "gobuster/3.6"',
        ],
        "sqli": [
            '192.168.1.100 - - [16/Nov/2026:08:01:10 +0000] "GET /vulnerabilities/sqli/?id=1%27%20UNION%20SELECT%20user,password%20FROM%20users-- HTTP/1.1" 200 4210 "-" "sqlmap/1.7"',
            '192.168.1.100 - - [16/Nov/2026:08:01:15 +0000] "GET /vulnerabilities/sqli/?id=1%27%20OR%201=1-- HTTP/1.1" 200 3800 "-" "Mozilla/5.0"',
        ],
        "bruteforce": [
            'Nov 16 08:02:00 victim sshd[3010]: Failed password for invalid user admin from 203.0.113.50 port 41200 ssh2',
            'Nov 16 08:02:02 victim sshd[3011]: Failed password for invalid user root from 203.0.113.50 port 41202 ssh2',
            'Nov 16 08:02:04 victim sshd[3012]: Failed password for invalid user ubuntu from 203.0.113.50 port 41204 ssh2',
            'Nov 16 08:02:06 victim sshd[3013]: Failed password for invalid user test from 203.0.113.50 port 41206 ssh2',
            'Nov 16 08:02:08 victim sshd[3014]: Failed password for invalid user guest from 203.0.113.50 port 41208 ssh2',
        ],
        "cmdi": [
            '192.168.1.105 - - [16/Nov/2026:08:03:00 +0000] "POST /vulnerabilities/exec/?ip=127.0.0.1;cat%20/etc/passwd HTTP/1.1" 200 1200 "-" "curl/8.4.0"',
        ],
        "lfi": [
            '185.220.101.5 - - [16/Nov/2026:08:04:00 +0000] "GET /vulnerabilities/fi/?page=../../../../../../etc/passwd HTTP/1.1" 200 1800 "-" "Mozilla/5.0"',
        ],
    }

    if scenario == "all":
        lines = []
        for s in ["recon", "sqli", "bruteforce", "cmdi", "lfi"]:
            lines.extend(scenarios[s])
        return lines
    return scenarios.get(scenario, scenarios["sqli"])


def run_pipeline(
    scenario: str = "all",
    db_path: str = "data/minisoc.duckdb",
    audit_path: str = "data/audit_log.jsonl",
    launch_dashboard: bool = False,
) -> dict:
    """Run the entire MiniSOC-AI pipeline end-to-end."""
    print("=" * 65)
    print("  MiniSOC-AI: 1-Command Automated End-to-End Pipeline & Demo")
    print("=" * 65)

    # 1. Generate attack logs
    raw_lines = generate_attack_scenarios(scenario)
    print(f"[*] Step 1: Simulating cyber attack scenario: '{scenario}' ({len(raw_lines)} events)")

    # 2. Ingestion & Threat Intel Enrichment
    store = DuckDBStore(db_path=db_path)
    parsed_events = []
    ti_hits = 0

    for line in raw_lines:
        ev = parse_line(line, log_source="demo_stream", enrich_ti=True)
        if ev:
            if "ti:match" in ev.tags:
                ti_hits += 1
            parsed_events.append(ev)

    inserted = store.insert_events(parsed_events)
    print(f"[+] Step 2: Ingested {inserted} events into DuckDB (Threat Intel Matches: {ti_hits})")

    # 3. Detection Engine
    conn = duckdb.connect(db_path)
    engine = DetectionEngine(db_conn=conn)
    rules_dir = str(Path(__file__).parent.parent / "detections" / "rules")
    loaded_rules = engine.load_rules_from_dir(rules_dir)
    alerts = engine.run_all_rules()
    conn.close()
    print(f"[+] Step 3: Evaluated {loaded_rules} detection rules -> Generated {len(alerts)} alerts")

    # 4. LLM Triage & Guardrails
    print("[*] Step 4: Dispatching alerts to LLM Triage with MITRE RAG & Hash Chain...")
    audit = AuditLog(log_path=audit_path)
    triage_coord = TriageCoordinator(audit_log=audit)

    triaged_count = 0
    for alert in alerts[:5]:  # triage up to 5 for fast demo
        alert_dict = {
            "alert_id": alert.alert_id,
            "rule_id": alert.rule_id,
            "severity": alert.severity.value.upper(),
            "description": alert.rule_title,
            "mitre_technique_id": alert.mitre_technique_id,
            "evidence": alert.evidence,
        }
        report = triage_coord.triage_alert(alert_dict)
        triaged_count += 1

    print(f"[+] Step 4: Triaged {triaged_count} alerts with policy enforcement & approval queuing")

    # 5. Check Hash Chain Integrity
    chain_valid, broken_at = audit.verify_chain()
    print(f"[+] Step 5: Cryptographic audit log verified: {'VALID (Tamper-Free)' if chain_valid else f'TAMPER DETECTED at {broken_at}'}")

    # 6. Summary metrics
    summary = {
        "events_simulated": len(raw_lines),
        "threat_intel_matches": ti_hits,
        "rules_evaluated": loaded_rules,
        "alerts_generated": len(alerts),
        "alerts_triaged": triaged_count,
        "audit_chain_valid": chain_valid,
    }

    print("\n" + "=" * 65)
    print("  EXECUTIVE SUMMARY")
    print("=" * 65)
    print(f"  - Simulated Events Ingested:    {summary['events_simulated']}")
    print(f"  - Threat Intel Matches Flagged: {summary['threat_intel_matches']}")
    print(f"  - Detection Rules Evaluated:    {summary['rules_evaluated']}")
    print(f"  - Security Alerts Generated:    {summary['alerts_generated']}")
    print(f"  - Triaged & Quarantined:        {summary['alerts_triaged']}")
    print(f"  - Audit Chain Verification:     {'100% VALID' if chain_valid else 'CORRUPTED'}")
    print("=" * 65)
    print("[*] Open the Web Dashboard with: streamlit run dashboard/app.py\n")

    store.close()

    if launch_dashboard:
        print("[*] Launching Streamlit dashboard...")
        subprocess.run(["streamlit", "run", "dashboard/app.py"])

    return summary


def main():
    parser = argparse.ArgumentParser(description="MiniSOC-AI 1-Command Demo Runner & Attack Simulator")
    parser.add_argument("--scenario", "-s", default="all", choices=["all", "recon", "sqli", "bruteforce", "cmdi", "lfi"])
    parser.add_argument("--db", default="data/minisoc.duckdb", help="Path to DuckDB database")
    parser.add_argument("--audit", default="data/audit_log.jsonl", help="Path to audit log file")
    parser.add_argument("--dashboard", "-d", action="store_true", help="Automatically launch Streamlit web dashboard")

    args = parser.parse_args()
    run_pipeline(
        scenario=args.scenario,
        db_path=args.db,
        audit_path=args.audit,
        launch_dashboard=args.dashboard,
    )


if __name__ == "__main__":
    main()
