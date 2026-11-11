"""Unit tests for MiniSOC-AI Machine Learning Module."""

from pathlib import Path
import numpy as np
import pytest

from ml.dataset import generate_synthetic_soc_dataset
from ml.features import LogFeatureExtractor, calculate_entropy
from ml.models import IsolationForestDetector, XGBoostDetector, load_models, save_models
from ml.evaluate import compute_metrics, run_experiment


def test_calculate_entropy():
    """Verify Shannon entropy calculation on uniform vs random strings."""
    # Zero entropy for identical characters
    assert calculate_entropy("aaaa") == 0.0
    # Higher entropy for random alphanumeric string
    assert calculate_entropy("a1!b2@c3#") > calculate_entropy("abcd")


def test_synthetic_dataset_generation():
    """Verify synthetic dataset generates expected distribution and time ordering."""
    df = generate_synthetic_soc_dataset(n_samples=500, attack_ratio=0.10, seed=123)
    assert len(df) == 500
    assert df["label"].sum() == 50  # 10% attacks
    # Verify strict temporal ordering
    assert df["timestamp"].is_monotonic_increasing


def test_feature_extractor_pipeline():
    """Verify feature extractor outputs correct dimensions and valid numbers."""
    df = generate_synthetic_soc_dataset(n_samples=200, attack_ratio=0.10, seed=42)
    extractor = LogFeatureExtractor(window_seconds=60)
    X = extractor.fit_transform(df)

    assert X.shape[0] == 200
    assert X.shape[1] == len(extractor.get_feature_names_out())
    # No NaNs or Infs
    assert not np.isnan(X).any()
    assert not np.isinf(X).any()


def test_model_training_and_serialization(tmp_path):
    """Verify Isolation Forest and XGBoost models train and serialize cleanly."""
    df = generate_synthetic_soc_dataset(n_samples=300, attack_ratio=0.10, seed=42)
    extractor = LogFeatureExtractor()
    X = extractor.fit_transform(df)
    y = df["label"].to_numpy()

    # Train Isolation Forest
    if_detector = IsolationForestDetector(n_estimators=20, contamination=0.10, random_state=42)
    if_detector.fit(X)
    if_preds = if_detector.predict(X)
    assert len(if_preds) == 300
    assert set(np.unique(if_preds)).issubset({0, 1})

    # Train XGBoost
    xgb_detector = XGBoostDetector(n_estimators=20, random_state=42)
    xgb_detector.fit(X, y)
    xgb_preds = xgb_detector.predict(X)
    assert len(xgb_preds) == 300
    assert set(np.unique(xgb_preds)).issubset({0, 1})

    # Test serialization
    save_dir = tmp_path / "models"
    save_models(if_detector, xgb_detector, output_dir=str(save_dir))
    loaded_if, loaded_xgb = load_models(model_dir=str(save_dir))

    assert loaded_if.is_fitted
    assert loaded_xgb.is_fitted
    np.testing.assert_array_equal(loaded_if.predict(X), if_preds)
    np.testing.assert_array_equal(loaded_xgb.predict(X), xgb_preds)


def test_compute_metrics():
    """Verify metric calculations on known predictions."""
    y_true = np.array([0, 0, 1, 1, 0, 1])
    y_pred = np.array([0, 0, 1, 0, 1, 1])  # 2 TP, 2 TN, 1 FP, 1 FN
    metrics = compute_metrics(y_true, y_pred)

    assert metrics["TP"] == 2
    assert metrics["TN"] == 2
    assert metrics["FP"] == 1
    assert metrics["FN"] == 1
    assert metrics["Precision"] == 2 / 3
    assert metrics["Recall"] == 2 / 3
