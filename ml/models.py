"""Machine Learning Detectors for MiniSOC-AI.

Implements:
1. IsolationForestDetector (Unsupervised Anomaly Detection)
2. XGBoostDetector (Supervised Classification with Class Imbalance Weighting)
"""

from pathlib import Path
from typing import Dict, Tuple
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
import xgboost as xgb


class IsolationForestDetector:
    """Unsupervised anomaly detection using Isolation Forest."""

    def __init__(self, n_estimators: int = 100, contamination: float = 0.08, random_state: int = 42):
        self.contamination = contamination
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray):
        """Fit Isolation Forest on features."""
        self.model.fit(X)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict binary class: 1 = Anomaly/Attack, 0 = Normal."""
        raw_preds = self.model.predict(X)
        # Isolation Forest returns -1 for anomaly and +1 for normal
        return np.where(raw_preds == -1, 1, 0)

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        """Invert decision function: higher value = higher anomaly likelihood."""
        return -self.model.decision_function(X)


class XGBoostDetector:
    """Supervised gradient boosting classifier for security events."""

    def __init__(
        self,
        n_estimators: int = 100,
        max_depth: int = 4,
        learning_rate: float = 0.1,
        scale_pos_weight: float = 10.0,
        random_state: int = 42,
    ):
        self.model = xgb.XGBClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            learning_rate=learning_rate,
            scale_pos_weight=scale_pos_weight,
            eval_metric="logloss",
            random_state=random_state,
            n_jobs=-1,
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        """Train supervised model on labeled feature matrix."""
        # Calculate scale_pos_weight dynamically if default
        n_neg = np.sum(y == 0)
        n_pos = np.sum(y == 1)
        if n_pos > 0:
            weight = n_neg / n_pos
            self.model.set_params(scale_pos_weight=weight)

        self.model.fit(X, y)
        self.is_fitted = True
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Predict binary class (0 = benign, 1 = attack)."""
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Predict attack probability."""
        return self.model.predict_proba(X)[:, 1]

    def get_feature_importances(self, feature_names: list) -> Dict[str, float]:
        """Return normalized feature importances."""
        importances = self.model.feature_importances_
        return dict(sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True))


def save_models(if_model: IsolationForestDetector, xgb_model: XGBoostDetector, output_dir: str = "ml/saved_models"):
    """Persist models to disk."""
    p = Path(output_dir)
    p.mkdir(parents=True, exist_ok=True)
    joblib.dump(if_model, p / "isolation_forest.joblib")
    joblib.dump(xgb_model, p / "xgboost.joblib")


def load_models(model_dir: str = "ml/saved_models") -> Tuple[IsolationForestDetector, XGBoostDetector]:
    """Load persisted models from disk."""
    p = Path(model_dir)
    if_model = joblib.load(p / "isolation_forest.joblib")
    xgb_model = joblib.load(p / "xgboost.joblib")
    return if_model, xgb_model
