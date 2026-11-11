"""MiniSOC-AI Rule-Based Detection Engine.

Loads Sigma-style rules, compiles them to DuckDB SQL queries, and generates structured Alerts.
"""

import hashlib
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
import duckdb
import pandas as pd

from detections.rule_schema import Alert, AlertStatus, DetectionRule, DetectionType, RuleSeverity


def generate_deterministic_alert_id(rule_id: str, matched_event_ids: List[str]) -> str:
    """Generate a stable fingerprint ID to ensure alert generation idempotency."""
    content = f"{rule_id}:{':'.join(sorted(matched_event_ids))}"
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:32]


class DetectionEngine:
    """Evaluates detection rules against normalized events stored in DuckDB."""

    def __init__(self, db_conn: duckdb.DuckDBPyConnection):
        """Initialize engine with an active DuckDB connection."""
        self.conn = db_conn
        self.rules: List[DetectionRule] = []
        self._init_alerts_table()

    def _init_alerts_table(self):
        """Initialize alerts table and index."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                rule_id VARCHAR NOT NULL,
                rule_title VARCHAR NOT NULL,
                severity VARCHAR NOT NULL,
                mitre_tactic VARCHAR NOT NULL,
                mitre_technique_id VARCHAR NOT NULL,
                mitre_technique_name VARCHAR NOT NULL,
                source_ip VARCHAR,
                target_user VARCHAR,
                matched_event_ids VARCHAR[],
                event_count INTEGER NOT NULL,
                evidence VARCHAR NOT NULL,
                status VARCHAR NOT NULL
            );
        """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_id);")
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_alerts_technique ON alerts(mitre_technique_id);")

    def load_rules_from_dir(self, rules_dir: str) -> int:
        """Scan directory and parse all YAML rule files."""
        p = Path(rules_dir)
        if not p.exists():
            return 0

        self.rules = []
        for file_path in p.glob("*.yml"):
            with open(file_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                rule = DetectionRule(**data)
                self.rules.append(rule)
        
        # Sort rules deterministically by rule id
        self.rules.sort(key=lambda r: r.id)
        return len(self.rules)

    def load_rule(self, rule: DetectionRule):
        """Add a single DetectionRule object."""
        self.rules.append(rule)

    def compile_rule_to_sql(self, rule: DetectionRule) -> str:
        """Compile a declarative DetectionRule into a DuckDB SQL query."""
        spec = rule.detection

        if spec.custom_sql:
            return spec.custom_sql

        conditions = ["1=1"]

        # Category filter
        if spec.event_category:
            conditions.append(f"event_category = '{spec.event_category}'")

        # Outcome filter
        if spec.event_outcome:
            conditions.append(f"event_outcome = '{spec.event_outcome}'")

        # HTTP methods
        if spec.http_methods:
            methods_str = ", ".join(f"'{m.upper()}'" for m in spec.http_methods)
            conditions.append(f"http_method IN ({methods_str})")

        # Status codes
        if spec.status_codes:
            codes_str = ", ".join(str(c) for c in spec.status_codes)
            conditions.append(f"http_status_code IN ({codes_str})")

        # URL patterns (searches both raw URL and URL-decoded/comment-normalized URL for evasion defense)
        if spec.url_patterns:
            url_clauses = []
            for pat in spec.url_patterns:
                escaped = pat.replace("'", "''").lower()
                url_clauses.append(f"lower(http_url) LIKE '%{escaped}%'")
                url_clauses.append(
                    f"replace(lower(url_decode(coalesce(http_url, ''))), '/**/', ' ') LIKE '%{escaped}%'"
                )
            conditions.append(f"({' OR '.join(url_clauses)})")

        # User-Agent patterns
        if spec.user_agent_patterns:
            ua_clauses = []
            for pat in spec.user_agent_patterns:
                escaped = pat.replace("'", "''").lower()
                ua_clauses.append(f"lower(http_user_agent) LIKE '%{escaped}%'")
            conditions.append(f"({' OR '.join(ua_clauses)})")

        # Raw event patterns
        if spec.raw_patterns:
            raw_clauses = []
            for pat in spec.raw_patterns:
                escaped = pat.replace("'", "''").lower()
                raw_clauses.append(f"lower(raw_event) LIKE '%{escaped}%'")
            conditions.append(f"({' OR '.join(raw_clauses)})")

        where_clause = " AND ".join(conditions)

        if spec.type == DetectionType.PATTERN:
            return f"""
                SELECT event_id, timestamp, source_ip, user_name, http_url, http_user_agent, raw_event
                FROM events
                WHERE {where_clause}
            """

        elif spec.type == DetectionType.THRESHOLD:
            group_cols = ", ".join(spec.group_by)
            return f"""
                SELECT {group_cols},
                       count(*) as event_count,
                       min(timestamp) as first_seen,
                       max(timestamp) as last_seen,
                       list(event_id) as matched_event_ids,
                       string_agg(DISTINCT coalesce(user_name, '-'), ', ') as target_users,
                       string_agg(DISTINCT coalesce(http_url, raw_event), ' | ') as sample_evidence
                FROM events
                WHERE {where_clause}
                GROUP BY {group_cols}
                HAVING count(*) >= {spec.threshold_count}
            """

        raise ValueError(f"Unsupported detection type: {spec.type}")

    def evaluate_rule(self, rule: DetectionRule) -> List[Alert]:
        """Evaluate a single rule against events and return generated alerts."""
        sql = self.compile_rule_to_sql(rule)
        cursor = self.conn.cursor()
        rel = cursor.execute(sql)
        cols = [desc[0] for desc in rel.description]
        rows = [dict(zip(cols, r)) for r in rel.fetchall()]
        cursor.close()

        alerts = []
        spec = rule.detection

        if spec.type == DetectionType.PATTERN:
            for r in rows:
                ev_id = r["event_id"]
                evidence = r.get("http_url") or r.get("raw_event") or "pattern match"
                alert_id = generate_deterministic_alert_id(rule.id, [ev_id])
                alerts.append(Alert(
                    alert_id=alert_id,
                    rule_id=rule.id,
                    rule_title=rule.title,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre.tactic,
                    mitre_technique_id=rule.mitre.technique_id,
                    mitre_technique_name=rule.mitre.technique_name,
                    source_ip=r.get("source_ip"),
                    target_user=r.get("user_name"),
                    matched_event_ids=[ev_id],
                    event_count=1,
                    evidence=f"Matched payload: {evidence}",
                    status=AlertStatus.NEW,
                ))

        elif spec.type in (DetectionType.THRESHOLD, DetectionType.CORRELATION):
            for r in rows:
                matched_ids = [str(x) for x in (r.get("matched_event_ids") or [])]
                evidence = r.get("sample_evidence") or f"Threshold met: {r.get('event_count')} occurrences"
                alert_id = generate_deterministic_alert_id(rule.id, matched_ids)
                alerts.append(Alert(
                    alert_id=alert_id,
                    rule_id=rule.id,
                    rule_title=rule.title,
                    severity=rule.severity,
                    mitre_tactic=rule.mitre.tactic,
                    mitre_technique_id=rule.mitre.technique_id,
                    mitre_technique_name=rule.mitre.technique_name,
                    source_ip=r.get("source_ip"),
                    target_user=r.get("target_users"),
                    matched_event_ids=matched_ids,
                    event_count=r.get("event_count", 1),
                    evidence=evidence,
                    status=AlertStatus.NEW,
                ))

        return alerts

    def run_all_rules(self) -> List[Alert]:
        """Run all loaded rules, store alerts in DuckDB alerts table, and return them."""
        all_alerts: List[Alert] = []
        for rule in self.rules:
            rule_alerts = self.evaluate_rule(rule)
            all_alerts.extend(rule_alerts)

        if all_alerts:
            df = pd.DataFrame([a.to_duckdb_row() for a in all_alerts])
            self.conn.register("batch_alerts_df", df)
            self.conn.execute("""
                INSERT OR IGNORE INTO alerts
                SELECT * FROM batch_alerts_df;
            """)
            self.conn.unregister("batch_alerts_df")

        return all_alerts

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch stored alerts ordered by timestamp descending."""
        cursor = self.conn.cursor()
        rel = cursor.execute("""
            SELECT * FROM alerts
            ORDER BY timestamp DESC
            LIMIT ?;
        """, [limit])
        cols = [desc[0] for desc in rel.description]
        rows = [dict(zip(cols, r)) for r in rel.fetchall()]
        cursor.close()
        return rows

    def get_mitre_coverage(self) -> List[Dict[str, Any]]:
        """Summarize active detection coverage by MITRE tactic and technique."""
        cursor = self.conn.cursor()
        rel = cursor.execute("""
            SELECT mitre_tactic, mitre_technique_id, mitre_technique_name,
                   count(*) as alert_count
            FROM alerts
            GROUP BY mitre_tactic, mitre_technique_id, mitre_technique_name
            ORDER BY alert_count DESC;
        """)
        cols = [desc[0] for desc in rel.description]
        rows = [dict(zip(cols, r)) for r in rel.fetchall()]
        cursor.close()
        return rows
