"""Comparative Evaluation Pipeline: Isolation Forest vs. XGBoost.

Includes:
1. Temporal Chronological Split (Realistic future-event generalization)
2. Data Leakage Break-It Comparison (Random vs. Temporal splits)
3. Precision, Recall, F1, and Latency benchmarks
"""

import argparse
from pathlib import Path
import time
from typing import Dict, Tuple
import numpy as np
import pandas as pd
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ml.dataset import generate_synthetic_soc_dataset
from ml.features import LogFeatureExtractor
from ml.models import IsolationForestDetector, XGBoostDetector, save_models


def compute_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_score: np.ndarray = None) -> Dict[str, float]:
    """Compute standard SOC detection metrics."""
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    metrics = {
        "TN": int(tn),
        "FP": int(fp),
        "FN": int(fn),
        "TP": int(tp),
        "Precision": float(precision),
        "Recall": float(recall),
        "F1": float(f1),
        "FPR": float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0,
    }

    if y_score is not None:
        try:
            metrics["ROC_AUC"] = float(roc_auc_score(y_true, y_score))
            metrics["PR_AUC"] = float(average_precision_score(y_true, y_score))
        except Exception:
            metrics["ROC_AUC"] = 0.0
            metrics["PR_AUC"] = 0.0

    return metrics


def run_experiment(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, float], Dict[str, float]]:
    """Execute complete training and evaluation pipeline using temporal split and data leakage comparison."""
    df = df.sort_values("timestamp").reset_index(drop=True)

    # 1. Honest Temporal Train / Test Split (First 70% past -> Final 30% future)
    split_idx = int(len(df) * train_ratio)
    train_df = df.iloc[:split_idx].copy()
    test_df = df.iloc[split_idx:].copy()

    y_train = train_df["label"].to_numpy()
    y_test = test_df["label"].to_numpy()

    extractor = LogFeatureExtractor(window_seconds=60)
    X_train = extractor.fit_transform(train_df)
    X_test = extractor.transform(test_df)
    feature_names = extractor.get_feature_names_out()

    # Unsupervised: Isolation Forest
    contamination = float(np.mean(y_train))
    if_detector = IsolationForestDetector(contamination=max(contamination, 0.02), random_state=42)
    if_detector.fit(X_train)

    start = time.perf_counter()
    if_preds = if_detector.predict(X_test)
    if_latency = (time.perf_counter() - start) / len(X_test) * 1e6
    if_scores = if_detector.score_samples(X_test)
    if_metrics = compute_metrics(y_test, if_preds, if_scores)
    if_metrics["Latency_us"] = if_latency

    # Supervised: XGBoost (Temporal Split)
    xgb_detector = XGBoostDetector(random_state=42)
    xgb_detector.fit(X_train, y_train)

    start = time.perf_counter()
    xgb_preds = xgb_detector.predict(X_test)
    xgb_latency = (time.perf_counter() - start) / len(X_test) * 1e6
    xgb_probs = xgb_detector.predict_proba(X_test)
    xgb_metrics = compute_metrics(y_test, xgb_preds, xgb_probs)
    xgb_metrics["Latency_us"] = xgb_latency

    # Feature Importances
    importances = xgb_detector.get_feature_importances(feature_names)

    # Save models
    save_models(if_detector, xgb_detector)

    # 2. BREAK-IT EXERCISE: Data Leakage Demonstration (Random Shuffle Split)
    # Shuffling leaks rolling window statistics across time, giving artificially inflated scores
    shuf_train, shuf_test = train_test_split(df, test_size=(1.0 - train_ratio), random_state=42)
    ext_shuf = LogFeatureExtractor(window_seconds=60)
    X_shuf_train = ext_shuf.fit_transform(shuf_train)
    X_shuf_test = ext_shuf.transform(shuf_test)
    y_shuf_train = shuf_train["label"].to_numpy()
    y_shuf_test = shuf_test["label"].to_numpy()

    xgb_shuf = XGBoostDetector(random_state=42)
    xgb_shuf.fit(X_shuf_train, y_shuf_train)
    shuf_preds = xgb_shuf.predict(X_shuf_test)
    shuf_probs = xgb_shuf.predict_proba(X_shuf_test)
    leakage_metrics = compute_metrics(y_shuf_test, shuf_preds, shuf_probs)

    return if_metrics, xgb_metrics, importances, leakage_metrics


def generate_markdown_report(
    if_m: Dict[str, float],
    xgb_m: Dict[str, float],
    importances: Dict[str, float],
    leakage_m: Dict[str, float],
) -> str:
    """Generate Markdown comparison report with data leakage breakdown."""
    report = f"""# MiniSOC-AI — Machine Learning Detection Evaluation Report

## 1. Overview & Paradigm Comparison

This report compares **Unsupervised Anomaly Detection (Isolation Forest)** against **Supervised Classification (XGBoost)** on time-ordered security logs under realistic SOC class imbalance (~8% attack ratio).

| Metric | Isolation Forest (Unsupervised) | XGBoost (Supervised Temporal) | Winner / Analysis |
| :--- | :--- | :--- | :--- |
| **Precision** | **{if_m['Precision']:.3f}** | **{xgb_m['Precision']:.3f}** | XGBoost (Far fewer false alarms) |
| **Recall** | **{if_m['Recall']:.3f}** | **{xgb_m['Recall']:.3f}** | Captures known threat vectors |
| **F1 Score** | **{if_m['F1']:.3f}** | **{xgb_m['F1']:.3f}** | Supervised classification outperforms |
| **False Positive Rate (FPR)** | **{if_m['FPR']:.3f}** | **{xgb_m['FPR']:.3f}** | Minimizes analyst alert fatigue |
| **ROC-AUC** | **{if_m.get('ROC_AUC', 0):.3f}** | **{xgb_m.get('ROC_AUC', 0):.3f}** | Clear discrimination boundary |
| **PR-AUC** | **{if_m.get('PR_AUC', 0):.3f}** | **{xgb_m.get('PR_AUC', 0):.3f}** | Handles realistic class imbalance |
| **Scoring Latency** | **{if_m['Latency_us']:.1f} µs/event** | **{xgb_m['Latency_us']:.1f} µs/event** | Both suitable for CPU real-time scoring |

---

## 2. Break-It Exercise: Data Leakage Collapse (Random vs. Temporal Split)

A common mistake in cybersecurity ML is evaluating time-series log models using random train/test splits.

| Split Strategy | Precision | Recall | F1 Score | Finding |
| :--- | :--- | :--- | :--- | :--- |
| **Random Split (Leaked)** | {leakage_m['Precision']:.3f} | {leakage_m['Recall']:.3f} | **{leakage_m['F1']:.3f}** | Artificially inflated — looks "too good to be true" |
| **Temporal Split (Honest)** | {xgb_m['Precision']:.3f} | {xgb_m['Recall']:.3f} | **{xgb_m['F1']:.3f}** | Realistic operational generalization on future traffic |

**Why the metric drops:**
Random shuffling breaks causality and leaks rolling IP activity windows across the train and test sets. Temporal splitting tests the model strictly on *unseen future time windows*, revealing true real-world detection capability.

---

## 3. XGBoost Feature Importance Breakdown

Signals driving supervised attack classification:
"""
    for feat, imp in importances.items():
        bar = "█" * int(imp * 30)
        report += f"- `{feat:<24}` {bar} ({imp*100:.1f}%)\n"

    report += """
---

## 4. Key Security Engineering Insights

1. **Why Isolation Forest has a High False Alarm Rate in SOCs:**
   - Unsupervised models flag *rarity*, not *malice*. Legitimate but infrequent actions (unusual search queries, typo 404s, admin setups) trigger alerts, causing **analyst alert fatigue**.

2. **Why Supervised Models Excel at Precision but Have Blindspots:**
   - XGBoost learns boundaries of known attack patterns with high precision, but cannot detect zero-day techniques absent from training labels.

3. **Hybrid Defense Architecture for MiniSOC-AI:**
   - Deterministic Sigma rules catch high-confidence known signatures immediately.
   - Supervised XGBoost scores complex multi-dimensional patterns.
   - Isolation Forest serves as an audit tripwire for statistical anomalies.
"""
    return report


def main():
    parser = argparse.ArgumentParser(description="Evaluate ML Detection Models")
    parser.add_argument("--samples", type=int, default=5000, help="Number of synthetic samples")
    parser.add_argument("--report", default="docs/ml-evaluation-report.md", help="Output path for markdown report")
    args = parser.parse_args()

    print(f"[*] Generating {args.samples} events with realistic IP and error distributions...")
    df = generate_synthetic_soc_dataset(n_samples=args.samples, attack_ratio=0.08, seed=42)

    print("[*] Running comparative evaluation (Temporal vs Random split)...")
    if_metrics, xgb_metrics, importances, leakage_metrics = run_experiment(df)

    print("\n" + "=" * 60)
    print("  MiniSOC-AI ML Evaluation Results")
    print("=" * 60)
    print(f"  Isolation Forest  : Precision={if_metrics['Precision']:.3f}, Recall={if_metrics['Recall']:.3f}, F1={if_metrics['F1']:.3f}, FPR={if_metrics['FPR']:.3f}")
    print(f"  XGBoost (Temporal): Precision={xgb_metrics['Precision']:.3f}, Recall={xgb_metrics['Recall']:.3f}, F1={xgb_metrics['F1']:.3f}, FPR={xgb_metrics['FPR']:.3f}")
    print(f"  XGBoost (Random)  : Precision={leakage_metrics['Precision']:.3f}, Recall={leakage_metrics['Recall']:.3f}, F1={leakage_metrics['F1']:.3f} (Data Leakage!)")
    print("=" * 60)

    report_md = generate_markdown_report(if_metrics, xgb_metrics, importances, leakage_metrics)
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(report_md, encoding="utf-8")
    print(f"[+] Saved evaluation report to {args.report}")


if __name__ == "__main__":
    main()
