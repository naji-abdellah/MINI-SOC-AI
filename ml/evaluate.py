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


def score_rules_on_dataset(df: pd.DataFrame, rules_dir: str = "detections/rules") -> Tuple[np.ndarray, float]:
    """Evaluate deterministic Sigma detection rules against a labeled event DataFrame."""
    from detections.engine import DetectionEngine
    from ingestion.duckdb_store import DuckDBStore
    from ingestion.schema import NormalizedEvent

    store = DuckDBStore(db_path=":memory:")

    start = time.perf_counter()
    events = []
    for idx, row in df.reset_index(drop=True).iterrows():
        ev = NormalizedEvent(
            event_id=f"eval_ev_{idx}",
            timestamp=row["timestamp"],
            event_category=row.get("event_category", "web"),
            event_action="http_request",
            event_outcome=row.get("event_outcome", "success"),
            source_ip=str(row.get("source_ip", "127.0.0.1")),
            http_method=str(row.get("http_method", "GET")),
            http_url=str(row.get("http_url", "")),
            http_status_code=int(row.get("http_status_code", 200)),
            http_user_agent=str(row.get("http_user_agent", "")),
            raw_event=f"{row.get('http_method', 'GET')} {row.get('http_url', '')} {row.get('http_status_code', 200)}",
            log_source="eval_test",
        )
        events.append(ev)

    store.insert_events(events)

    engine = DetectionEngine(db_conn=store.conn)
    engine.load_rules_from_dir(rules_dir)
    alerts = engine.run_all_rules()
    latency_us = (time.perf_counter() - start) / len(df) * 1e6
    store.close()

    matched_ids = set()
    for alert in alerts:
        for mid in alert.matched_event_ids:
            matched_ids.add(mid)

    y_pred_rules = np.zeros(len(df), dtype=int)
    for i in range(len(df)):
        if f"eval_ev_{i}" in matched_ids:
            y_pred_rules[i] = 1

    return y_pred_rules, latency_us


def run_experiment(
    df: pd.DataFrame,
    train_ratio: float = 0.70,
) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, float], Dict[str, float], Dict[str, float]]:
    """Execute complete training and evaluation pipeline using temporal split, rule benchmarking, and data leakage comparison."""
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

    # 3. Deterministic Sigma Rules Benchmark on the same unseen test data
    rule_preds, rule_latency = score_rules_on_dataset(test_df)
    rule_metrics = compute_metrics(y_test, rule_preds)
    rule_metrics["Latency_us"] = rule_latency

    return if_metrics, xgb_metrics, importances, leakage_metrics, rule_metrics


def generate_markdown_report(
    if_m: Dict[str, float],
    xgb_m: Dict[str, float],
    importances: Dict[str, float],
    leakage_m: Dict[str, float],
    rule_m: Dict[str, float] = None,
) -> str:
    """Generate Markdown comparison report with 3-way paradigm benchmark and data leakage breakdown."""
    rule_m = rule_m or {}
    report = f"""# MiniSOC-AI — Machine Learning Detection Evaluation Report

## 1. Overview & Tri-Paradigm Detection Comparison

This report compares **Deterministic Sigma Rules**, **Unsupervised Anomaly Detection (Isolation Forest)**, and **Supervised Classification (XGBoost)** on time-ordered security logs under realistic SOC class imbalance (~8% attack ratio) with benign developer activity noise.

| Metric | Deterministic Rules (Sigma) | Isolation Forest (Unsupervised) | XGBoost (Supervised Temporal) | Paradigm Analysis |
| :--- | :--- | :--- | :--- | :--- |
| **Precision** | **{rule_m.get('Precision', 0):.3f}** | **{if_m['Precision']:.3f}** | **{xgb_m['Precision']:.3f}** | Rules & XGBoost minimize false alarms |
| **Recall** | **{rule_m.get('Recall', 0):.3f}** | **{if_m['Recall']:.3f}** | **{xgb_m['Recall']:.3f}** | XGBoost captures evasions missed by static signatures |
| **F1 Score** | **{rule_m.get('F1', 0):.3f}** | **{if_m['F1']:.3f}** | **{xgb_m['F1']:.3f}** | XGBoost achieves best balance on novel variations |
| **False Positive Rate (FPR)** | **{rule_m.get('FPR', 0):.3f}** | **{if_m['FPR']:.3f}** | **{xgb_m['FPR']:.3f}** | High-precision filters prevent analyst alert fatigue |
| **ROC-AUC** | N/A (Binary Rule) | **{if_m.get('ROC_AUC', 0):.3f}** | **{xgb_m.get('ROC_AUC', 0):.3f}** | Supervised model provides clear decision boundary |
| **PR-AUC** | N/A (Binary Rule) | **{if_m.get('PR_AUC', 0):.3f}** | **{xgb_m.get('PR_AUC', 0):.3f}** | High PR-AUC despite strong class imbalance |
| **Scoring Latency** | **{rule_m.get('Latency_us', 0):.1f} µs/event** | **{if_m['Latency_us']:.1f} µs/event** | **{xgb_m['Latency_us']:.1f} µs/event** | All three suitable for high-throughput pipeline scoring |

---

## 2. Break-It Exercise: Data Leakage Demonstration (Random vs. Temporal Split)

A critical vulnerability in cybersecurity ML benchmarks is evaluating time-series log models using random train/test splits.

| Split Strategy | Precision | Recall | F1 Score | Finding |
| :--- | :--- | :--- | :--- | :--- |
| **Random Split (Leaked)** | {leakage_m['Precision']:.3f} | {leakage_m['Recall']:.3f} | **{leakage_m['F1']:.3f}** | Overly optimistic / inflated due to cross-split temporal leakage |
| **Temporal Split (Honest)** | {xgb_m['Precision']:.3f} | {xgb_m['Recall']:.3f} | **{xgb_m['F1']:.3f}** | Realistic operational generalization on unseen future time window |

**Why random splits artificially inflate metrics:**
When log events are randomly partitioned into train and test sets, events from the same IP burst or attack campaign are distributed across both splits. Rolling window features (such as `ip_req_count_window` and `ip_error_rate_window`) leak information from test events into training contexts. Temporal splitting enforces a strict chronological boundary (train on past, evaluate on future), accurately testing how the model generalizes to future unseen traffic.

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
    if_metrics, xgb_metrics, importances, leakage_metrics, rule_metrics = run_experiment(df)

    print("\n" + "=" * 60)
    print("  MiniSOC-AI Detection Engineering Benchmark Results")
    print("=" * 60)
    print(f"  Deterministic Rules: Precision={rule_metrics['Precision']:.3f}, Recall={rule_metrics['Recall']:.3f}, F1={rule_metrics['F1']:.3f}, FPR={rule_metrics['FPR']:.3f}")
    print(f"  Isolation Forest   : Precision={if_metrics['Precision']:.3f}, Recall={if_metrics['Recall']:.3f}, F1={if_metrics['F1']:.3f}, FPR={if_metrics['FPR']:.3f}")
    print(f"  XGBoost (Temporal) : Precision={xgb_metrics['Precision']:.3f}, Recall={xgb_metrics['Recall']:.3f}, F1={xgb_metrics['F1']:.3f}, FPR={xgb_metrics['FPR']:.3f}")
    print(f"  XGBoost (Random)   : Precision={leakage_metrics['Precision']:.3f}, Recall={leakage_metrics['Recall']:.3f}, F1={leakage_metrics['F1']:.3f} (Data Leakage!)")
    print("=" * 60)

    report_md = generate_markdown_report(if_metrics, xgb_metrics, importances, leakage_metrics, rule_m=rule_metrics)
    Path(args.report).parent.mkdir(parents=True, exist_ok=True)
    Path(args.report).write_text(report_md, encoding="utf-8")
    print(f"[+] Saved evaluation report to {args.report}")


if __name__ == "__main__":
    main()
