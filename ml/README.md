# Machine Learning Detection Module

## Purpose
Feature engineering, training, and comparative evaluation of:
1. **Unsupervised Anomaly Detection:** Isolation Forest.
2. **Supervised Classification:** XGBoost.

## Implementation Status (Milestone 3)
- [x] Feature extraction pipeline with Shannon URL entropy, token indicators, and sliding window features (`features.py`).
- [x] Unsupervised Isolation Forest baseline model for zero-day anomaly detection (`models.py`).
- [x] Supervised XGBoost classification model trained on realistic time-ordered traffic (`models.py`, `dataset.py`).
- [x] Metric evaluation and comparative benchmark reporting (`evaluate.py`, `docs/ml-evaluation-report.md`).
- [x] Data leakage break-it experiment (Temporal vs. Random split) and attack mix concept drift break-it test (`tests/test_ml_break_it.py`).
- [x] Active learning loop with validation-calibrated threshold adjustments from analyst feedback (`active_learning.py`).
