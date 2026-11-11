"""MiniSOC-AI Ingestion Command-Line Interface.

Usage:
    python -m ingestion.cli --input data/samples/dvwa_access.log --source dvwa
    python -m ingestion.cli --input data/samples/juiceshop_docker.jsonl --source juiceshop
    python -m ingestion.cli --stats
"""

import argparse
import sys
from pathlib import Path
from ingestion.dispatcher import parse_file
from ingestion.duckdb_store import DuckDBStore


def main():
    parser = argparse.ArgumentParser(description="MiniSOC-AI Log Ingestion & Analytics CLI")
    parser.add_argument("--input", "-i", help="Path to raw log file to ingest")
    parser.add_argument("--source", "-s", default="generic", help="Log source name (dvwa, juiceshop, auth_log, etc.)")
    parser.add_argument("--db", default="data/minisoc.duckdb", help="Path to DuckDB database file (or :memory:)")
    parser.add_argument("--stats", action="store_true", help="Display current database SIEM statistics")

    args = parser.parse_args()

    store = DuckDBStore(db_path=args.db)

    if args.input:
        input_path = Path(args.input)
        if not input_path.exists():
            print(f"[!] Error: File not found: {args.input}", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Ingesting: {input_path} (source: {args.source}) -> {args.db}")
        events = list(parse_file(str(input_path), log_source=args.source))
        inserted = store.insert_events(events)
        print(f"[+] Successfully parsed and stored {inserted} events.")

    if args.stats or args.input:
        total = store.count_events()
        print("\n" + "=" * 50)
        print(f"[SIEM] MiniSOC-AI Overview (Total Events: {total})")
        print("=" * 50)

        # Top IPs
        top_ips = store.get_top_source_ips(limit=5)
        print("\nTop Source IPs:")
        for r in top_ips:
            print(f"  - {r['source_ip']:<18} total: {r['event_count']:<4} failures: {r['failure_count']}")

        # Failed Logins
        failed = store.get_failed_logins_by_ip(threshold=2)
        if failed:
            print("\nSuspicious Authentication Failures (>= 2 attempts):")
            for f in failed:
                print(f"  - IP: {f['source_ip']} Target Users: [{f['target_users']}] Attempts: {f['failed_attempts']}")

        # HTTP error distribution
        err_dist = store.get_http_error_distribution()
        if err_dist:
            print("\nHTTP Status Code Distribution:")
            for e in err_dist:
                print(f"  - Status {e['http_status_code']}: {e['count']} events")
        print("=" * 50)

    store.close()


if __name__ == "__main__":
    main()
