# MiniSOC-AI — Machine Learning Detection Evaluation Report

## 1. Overview & Paradigm Comparison

This report compares **Unsupervised Anomaly Detection (Isolation Forest)** against **Supervised Classification (XGBoost)** on time-ordered security logs under realistic SOC class imbalance (~8% attack ratio).

| Metric | Isolation Forest (Unsupervised) | XGBoost (Supervised) | Winner / Analysis |
| :--- | :--- | :--- | :--- |
| **Precision** | **0.835** | **0.991** | XGBoost (Far fewer false alarms) |
| **Recall** | **0.741** | **0.991** | XGBoost captures known patterns with high fidelity |
| **F1 Score** | **0.785** | **0.991** | XGBoost significantly outperforms |
| **False Positive Rate (FPR)** | **0.012** | **0.001** | XGBoost minimizes analyst fatigue |
| **ROC-AUC** | **0.969** | **1.000** | Supervised discrimination |
| **PR-AUC** | **0.855** | **0.999** | XGBoost dominates under class imbalance |
| **Scoring Latency** | **10.6 µs/event** | **4.2 µs/event** | Both suitable for CPU real-time scoring |

---

## 2. Detailed Confusion Matrices

### Isolation Forest (Unsupervised)
- **True Negatives (TN):** 1367 (Correctly passed benign traffic)
- **False Positives (FP):** 17 (**Alert fatigue:** Benign events flagged as outliers)
- **False Negatives (FN):** 30 (Missed attacks)
- **True Positives (TP):** 86 (Caught attacks)

### XGBoost (Supervised)
- **True Negatives (TN):** 1383
- **False Positives (FP):** 1
- **False Negatives (FN):** 1
- **True Positives (TP):** 115

---

## 3. XGBoost Feature Importance Breakdown

Top signals driving supervised attack classification:
- `ip_error_rate_window    ` ████████████ (40.9%)
- `suspicious_token_count  ` █████████ (32.2%)
- `url_entropy             ` █████ (19.0%)
- `is_scanner_ua           `  (3.2%)
- `status_code             `  (1.5%)
- `is_post                 `  (1.1%)
- `is_error                `  (1.0%)
- `url_len                 `  (0.5%)
- `ip_req_count_window     `  (0.4%)
- `ip_error_count_window   `  (0.2%)

---

## 4. Key Security Engineering Insights

1. **Why Isolation Forest has a High False Alarm Rate in SOCs:**
   - Unsupervised models flag *rarity*, not *malice*. In real web traffic, legitimate but infrequent actions (e.g. users typing unusual search terms, administrative setup requests, error spikes) look like outliers to an Isolation Forest.
   - This leads to a low precision rate, causing severe **analyst alert fatigue**.

2. **Why Supervised Models Excel at Precision but Have Blindspots:**
   - XGBoost learns the precise boundaries of known attack patterns (e.g. `suspicious_token_count`, `url_len`, scanner user agents), yielding high precision and recall.
   - *However*, supervised models suffer from out-of-distribution blindspots: if an attacker uses a novel zero-day technique not present in training data, the model will classify it as benign.

3. **Hybrid Defense Architecture for MiniSOC-AI:**
   - Deterministic Sigma rules catch high-confidence known signatures immediately.
   - Supervised XGBoost scores complex multi-dimensional patterns (request rates + entropy).
   - Isolation Forest serves as a secondary tripwire for statistical outliers that pass standard filters.
