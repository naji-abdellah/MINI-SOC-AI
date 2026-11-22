"""Pytest configuration and global fixtures for MiniSOC-AI.

Prevents test pollution by redirecting DuckDB and audit log storage
to temporary directories during automated test execution.
"""

import os
from pathlib import Path
import pytest


@pytest.fixture(autouse=True)
def isolate_test_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Automatically point all database and audit log operations to tmp_path."""
    test_db = str(tmp_path / "test_minisoc.duckdb")
    test_audit = str(tmp_path / "test_audit_log.jsonl")

    monkeypatch.setenv("MINISOC_DB", test_db)
    monkeypatch.setenv("AUDIT_LOG_PATH", test_audit)

    yield {
        "db_path": test_db,
        "audit_path": test_audit,
        "tmp_path": tmp_path,
    }
