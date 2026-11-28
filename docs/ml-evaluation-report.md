# MiniSOC-AI — Machine Learning Detection Evaluation Report

## 1. Overview & Tri-Paradigm Detection Comparison

This report compares **Deterministic Sigma Rules**, **Unsupervised Anomaly Detection (Isolation Forest)**, and **Supervised Classification (XGBoost)** on time-ordered security logs under realistic SOC class imbalance (~8% attack ratio) with benign developer activity noise.

| Metric | Deterministic Rules (Sigma) | Isolation Forest (Unsupervised) | XGBoost (Supervised Temporal) | Paradigm Analysis |
| :--- | :--- | :--- | :--- | :--- |
| **Precision** | **1.000** | **0.420** | **0.884** | Rules & XGBoost minimize false alarms |
| **Recall** | **0.905** | **0.517** | **0.983** | XGBoost captures evasions missed by static signatures |
| **F1 Score** | **0.950** | **0.463** | **0.931** | XGBoost achieves best balance on novel variations |
| **False Positive Rate (FPR)** | **0.000** | **0.060** | **0.011** | High-precision filters prevent analyst alert fatigue |
| **ROC-AUC** | N/A (Binary Rule) | **0.886** | **0.997** | Supervised model provides clear decision boundary |
| **PR-AUC** | N/A (Binary Rule) | **0.507** | **0.979** | High PR-AUC despite strong class imbalance |
| **Scoring Latency** | **358.3 µs/event** | **11.9 µs/event** | **1.9 µs/event** | All three suitable for high-throughput pipeline scoring |

---

## 2. Break-It Exercise: Data Leakage Demonstration (Random vs. Temporal Split)

A critical vulnerability in cybersecurity ML benchmarks is evaluating time-series log models using random train/test splits.

| Split Strategy | Precision | Recall | F1 Score | Finding |
| :--- | :--- | :--- | :--- | :--- |
| **Random Split (Leaked)** | 0.954 | 0.992 | **0.973** | Overly optimistic / inflated due to cross-split temporal leakage |
| **Temporal Split (Honest)** | 0.884 | 0.983 | **0.931** | Realistic operational generalization on unseen future time window |

**Why random splits artificially inflate metrics:**
When log events are randomly partitioned into train and test sets, events from the same IP burst or attack campaign are distributed across both splits. Rolling window features (such as `ip_req_count_window` and `ip_error_rate_window`) leak information from test events into training contexts. Temporal splitting enforces a strict chronological boundary (train on past, evaluate on future), accurately testing how the model generalizes to future unseen traffic.

---

## 3. XGBoost Feature Importance Breakdown

Signals driving supervised attack classification:
- `is_error                ` ███████████ (37.8%)
- `suspicious_token_count  ` ██████ (20.0%)
- `is_scanner_ua           ` ██ (9.6%)
- `url_len                 ` ██ (9.5%)
- `status_code             ` ██ (7.4%)
- `url_entropy             ` █ (6.6%)
- `is_post                 ` █ (5.5%)
- `ip_error_rate_window    ` █ (3.5%)
- `ip_req_count_window     `  (0.0%)
- `ip_error_count_window   `  (0.0%)

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
