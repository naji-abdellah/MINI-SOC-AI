"""Unit tests for Active Learning Feedback Loop (ml/active_learning.py)."""

from datetime import datetime, timezone
import pytest
import duckdb
from ml.active_learning import ActiveLearningLoop
from dashboard.data import store_feedback


@pytest.fixture
def mock_feedback_db(tmp_path):
    db_file = str(tmp_path / "test_feedback.duckdb")
    store_feedback("alert-001", was_fp=True, comment="False positive: internal security scan", db_path=db_file)
    store_feedback("alert-002", was_fp=True, comment="False positive: admin dev script", db_path=db_file)
    store_feedback("alert-003", was_fp=False, comment="True positive: actual SQL injection", db_path=db_file)
    return db_file


def test_fetch_feedback(mock_feedback_db):
    loop = ActiveLearningLoop(db_path=mock_feedback_db)
    records = loop.fetch_feedback()
    assert len(records) == 3
    fps = [r for r in records if r["was_fp"]]
    tps = [r for r in records if not r["was_fp"]]
    assert len(fps) == 2
    assert len(tps) == 1


def test_active_learning_cycle_with_feedback(mock_feedback_db):
    loop = ActiveLearningLoop(db_path=mock_feedback_db)
    result = loop.run_active_learning_cycle(base_samples=500, decision_threshold=0.5)

    assert result["feedback_records_analyzed"] == 3
    assert result["false_positives_flagged_by_analysts"] == 2
    assert result["true_positives_confirmed_by_analysts"] == 1
    # Check that threshold was shifted upwards to suppress FPs
    assert result["calibrated_threshold"] > result["baseline_threshold"]
    # Calibrated false positives should be <= baseline false positives
    assert result["calibrated_false_positives"] <= result["baseline_false_positives"]
    assert result["retained_true_positives"] > 0


def test_active_learning_empty_db(tmp_path):
    empty_db = str(tmp_path / "empty.duckdb")
    loop = ActiveLearningLoop(db_path=empty_db)
    records = loop.fetch_feedback()
    assert records == []
    # Should run smoothly with defaults
    result = loop.run_active_learning_cycle(base_samples=300)
    assert result["feedback_records_analyzed"] == 0
