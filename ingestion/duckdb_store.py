"""DuckDB Events Store for MiniSOC-AI.

Provides high-performance, in-process analytical storage for normalized security events.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import duckdb
from ingestion.schema import NormalizedEvent


class DuckDBStore:
    """Manages DuckDB database initialization, batch ingestion, and analytical SIEM queries."""

    def __init__(self, db_path: str = ":memory:"):
        """Initialize connection. Pass a file path (e.g. 'data/minisoc.duckdb') or ':memory:'."""
        self.db_path = db_path
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = duckdb.connect(database=db_path)
        self._init_schema()

    def _init_schema(self):
        """Create normalized events table and analytical indexes."""
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id VARCHAR PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                event_category VARCHAR NOT NULL,
                event_action VARCHAR NOT NULL,
                event_outcome VARCHAR NOT NULL,
                source_ip VARCHAR,
                source_port INTEGER,
                destination_ip VARCHAR,
                destination_port INTEGER,
                http_method VARCHAR,
                http_url VARCHAR,
                http_status_code INTEGER,
                http_user_agent VARCHAR,
                user_name VARCHAR,
                log_source VARCHAR NOT NULL,
                raw_event VARCHAR NOT NULL,
                tags VARCHAR[]
            );
        """)

        # Analytical index on timestamp and category for range queries
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_category ON events(event_category);
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
        """)

    def insert_events(self, events: List[NormalizedEvent]) -> int:
        """Batch insert a list of NormalizedEvents into the database."""
        if not events:
            return 0

        rows = [e.to_duckdb_row() for e in events]
        # Register in-memory python dictionary for vectorized insert
        import pandas as pd
        df = pd.DataFrame(rows)

        before = self.count_events()
        self.conn.register("batch_df", df)
        self.conn.execute("""
            INSERT OR IGNORE INTO events
            SELECT * FROM batch_df;
        """)
        self.conn.unregister("batch_df")
        after = self.count_events()
        return after - before

    def count_events(self) -> int:
        """Return total event count."""
        cur = self.conn.cursor()
        res = cur.execute("SELECT count(*) FROM events;").fetchone()
        cur.close()
        return res[0] if res else 0

    def query(self, sql: str, params: Optional[List[Any]] = None) -> List[Dict[str, Any]]:
        """Execute arbitrary analytical SQL query and return rows as dictionaries."""
        cursor = self.conn.cursor()
        if params:
            rel = cursor.execute(sql, params)
        else:
            rel = cursor.execute(sql)

        columns = [desc[0] for desc in rel.description]
        results = []
        for row in rel.fetchall():
            results.append(dict(zip(columns, row)))
        return results

    def get_top_source_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Identify top requesting IP addresses and their event count."""
        return self.query("""
            SELECT source_ip, count(*) as event_count,
                   count(CASE WHEN event_outcome = 'failure' THEN 1 END) as failure_count
            FROM events
            WHERE source_ip IS NOT NULL
            GROUP BY source_ip
            ORDER BY event_count DESC
            LIMIT ?;
        """, [limit])

    def get_failed_logins_by_ip(self, threshold: int = 3) -> List[Dict[str, Any]]:
        """Detect brute force / credential spray candidates: IPs with multiple failed logins."""
        return self.query("""
            SELECT source_ip,
                   string_agg(DISTINCT user_name, ', ') as target_users,
                   count(*) as failed_attempts,
                   min(timestamp) as first_seen,
                   max(timestamp) as last_seen
            FROM events
            WHERE event_category = 'authentication' AND event_outcome = 'failure'
            GROUP BY source_ip
            HAVING count(*) >= ?
            ORDER BY failed_attempts DESC;
        """, [threshold])

    def get_http_error_distribution(self) -> List[Dict[str, Any]]:
        """HTTP response code distribution for anomaly detection."""
        return self.query("""
            SELECT http_status_code, count(*) as count
            FROM events
            WHERE http_status_code IS NOT NULL
            GROUP BY http_status_code
            ORDER BY count DESC;
        """)

    def close(self):
        """Close connection to release file lock."""
        self.conn.close()
