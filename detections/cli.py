"""MiniSOC-AI Detection Engine CLI.

Evaluates detection rules against DuckDB events and displays triggered alerts and MITRE coverage.

Usage:
    python -m detections.cli --rules detections/rules/ --db data/minisoc.duckdb
    python -m detections.cli --coverage --db data/minisoc.duckdb
"""

import argparse
import sys
from pathlib import Path
import duckdb

from detections.engine import DetectionEngine


def main():
    parser = argparse.ArgumentParser(description="MiniSOC-AI Detection Engine CLI")
    parser.add_argument("--rules", "-r", default="detections/rules", help="Path to detection rules directory")
    parser.add_argument("--db", default="data/minisoc.duckdb", help="Path to DuckDB database file")
    parser.add_argument("--coverage", action="store_true", help="Display MITRE ATT&CK coverage statistics")

    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists() and args.db != ":memory:":
        print(f"[!] Database file not found: {args.db}", file=sys.stderr)
        sys.exit(1)

    conn = duckdb.connect(database=args.db)
    engine = DetectionEngine(db_conn=conn)

    rule_count = engine.load_rules_from_dir(args.rules)
    print(f"[*] Loaded {rule_count} detection rules from: {args.rules}")

    alerts = engine.run_all_rules()
    print(f"[+] Evaluated rules. Generated {len(alerts)} alerts.")

    print("\n" + "=" * 60)
    print(f"[ALERTS] Active Incident Queue ({len(alerts)} alerts generated)")
    print("=" * 60)

    for a in alerts:
        print(f"[{a.severity.value.upper()}] {a.rule_title}")
        print(f"   MITRE:    {a.mitre_tactic} -> {a.mitre_technique_id} ({a.mitre_technique_name})")
        print(f"   Attacker: {a.source_ip or 'unknown'} | Target: {a.target_user or 'N/A'}")
        print(f"   Evidence: {a.evidence[:90]}...")
        print("-" * 60)

    if args.coverage or True:
        cov = engine.get_mitre_coverage()
        print("\n" + "=" * 60)
        print("[MITRE ATT&CK] Coverage Matrix")
        print("=" * 60)
        for c in cov:
            print(f"  - [{c['mitre_technique_id']}] {c['mitre_technique_name']:<35} ({c['mitre_tactic']}) -> {c['alert_count']} alert(s)")
        print("=" * 60)

    conn.close()


if __name__ == "__main__":
    main()
