"""Milestone 3 Break-It Exercise: Concept Drift and Attack Mix Shift.

Requirement from context.md:
"Break-it exercise: change the attack mix between train and test and observe the metrics collapse."

Demonstrates why supervised models (XGBoost) fail when attackers introduce novel techniques
not represented in the training baseline.
"""

import numpy as np
import pytest

from ml.dataset import generate_synthetic_soc_dataset
from ml.features import LogFeatureExtractor
from ml.models import IsolationForestDetector, XGBoostDetector
from ml.evaluate import compute_metrics


def test_break_it_attack_mix_shift_metrics_collapse():
    """Demonstrate supervised model collapse when test attack mix diverges from training data.
    
    Training Set: Benign + SQLi + Brute Force (Attacks known to model)
    Test Set: Benign + Command Injection (Novel attack never seen in training)
    """
    # 1. Generate full dataset
    df = generate_synthetic_soc_dataset(n_samples=2500, attack_ratio=0.15, seed=42)

    # 2. Construct Train Set: ONLY benign, sqli, and brute_force (EXCLUDE cmdi)
    train_mask = df["attack_type"].isin(["benign", "sqli", "brute_force"])
    train_df = df[train_mask].copy().reset_index(drop=True)

    # 3. Construct In-Distribution Test Set (same attack types: sqli & brute force)
    in_dist_test_df = df[train_mask].tail(400).copy().reset_index(drop=True)

    # 4. Construct Out-of-Distribution Test Set: Benign + ONLY cmdi (Novel attack!)
    ood_mask = df["attack_type"].isin(["benign", "cmdi"])
    ood_test_df = df[ood_mask].copy().reset_index(drop=True)

    # Feature extraction fitted ONLY on training set
    extractor = LogFeatureExtractor(window_seconds=60)
    X_train = extractor.fit_transform(train_df)
    y_train = train_df["label"].to_numpy()

    X_in_dist = extractor.transform(in_dist_test_df)
    y_in_dist = in_dist_test_df["label"].to_numpy()

    X_ood = extractor.transform(ood_test_df)
    y_ood = ood_test_df["label"].to_numpy()

    # Train Supervised XGBoost
    xgb = XGBoostDetector(n_estimators=50, random_state=42)
    xgb.fit(X_train, y_train)

    # In-distribution evaluation
    in_dist_preds = xgb.predict(X_in_dist)
    in_dist_metrics = compute_metrics(y_in_dist, in_dist_preds)

    # Out-of-distribution evaluation (novel attack)
    ood_preds = xgb.predict(X_ood)
    ood_metrics = compute_metrics(y_ood, ood_preds)

    # OBSERVATION & ASSERTION OF METRICS COLLAPSE:
    # On known attacks (SQLi, Brute force), XGBoost recall is very high
    assert in_dist_metrics["Recall"] >= 0.85, f"Expected high recall on known attacks, got {in_dist_metrics['Recall']}"

    # On novel command injection attacks, recall drops significantly!
    # Because command injection doesn't use SQL keywords or POST login endpoints
    assert ood_metrics["Recall"] < in_dist_metrics["Recall"], (
        f"Expected recall to collapse on novel attack! In-dist: {in_dist_metrics['Recall']:.2f}, OOD: {ood_metrics['Recall']:.2f}"
    )

    # Document the exact gap
    recall_drop = in_dist_metrics["Recall"] - ood_metrics["Recall"]
    assert recall_drop > 0.20, f"Expected at least 20% recall degradation on unseen attacks, got {recall_drop*100:.1f}%"
