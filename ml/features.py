"""Feature Engineering Pipeline for MiniSOC-AI Machine Learning.

Transforms raw security log events into numeric feature vectors using lexical analysis,
information theory (entropy), and sliding-window temporal aggregations.
"""

from collections import Counter
import math
import re
from typing import List
import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin


SUSPICIOUS_TOKENS = [
    "union",
    "select",
    "../",
    "..%2f",
    "etc/passwd",
    "etc/shadow",
    "cat ",
    "whoami",
    ";",
    "|",
    "sleep(",
    "<script",
    "alert(",
    ".env",
    "phpinfo",
    "wp-admin",
]

KNOWN_SCANNER_PATTERNS = [
    "sqlmap",
    "nikto",
    "gobuster",
    "dirbuster",
    "hydra",
    "curl",
    "nmap",
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string (higher = more random/encoded)."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class LogFeatureExtractor(BaseEstimator, TransformerMixin):
    """Transforms raw event DataFrame into machine learning features."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self.feature_names_: List[str] = []

    def fit(self, X: pd.DataFrame, y=None):
        return self

    def transform(self, X: pd.DataFrame) -> np.ndarray:
        """Extract features from DataFrame."""
        df = X.copy().reset_index(drop=True)
        df["_pos"] = range(len(df))

        # Ensure timestamp is datetime
        if not pd.api.types.is_datetime64_any_dtype(df["timestamp"]):
            df["timestamp"] = pd.to_datetime(df["timestamp"])

        # 1. Lexical features on URL
        df["url_len"] = df["http_url"].fillna("").astype(str).str.len()
        df["url_entropy"] = df["http_url"].fillna("").astype(str).apply(calculate_entropy)

        # Suspicious keyword count
        def count_suspicious(url: str) -> int:
            url_lower = str(url).lower()
            return sum(1 for token in SUSPICIOUS_TOKENS if token in url_lower)

        df["suspicious_token_count"] = df["http_url"].apply(count_suspicious)

        # 2. HTTP Method & Status
        df["is_post"] = (df["http_method"] == "POST").astype(int)
        df["is_error"] = (df["http_status_code"] >= 400).astype(int)
        df["status_code"] = df["http_status_code"].fillna(200).astype(int)

        # 3. User-Agent Scanner signature
        def is_scanner(ua: str) -> int:
            ua_lower = str(ua).lower()
            return int(any(p in ua_lower for p in KNOWN_SCANNER_PATTERNS))

        df["is_scanner_ua"] = df["http_user_agent"].apply(is_scanner)

        # 4. Temporal sliding window features per IP
        # Group by source_ip and compute rolling metrics
        df = df.sort_values("timestamp")
        
        # Calculate rolling request rates per IP using time-based window
        df["ip_req_count_window"] = 1.0
        df["ip_error_count_window"] = 0.0

        # Fast group-wise rolling calculation
        for ip, group in df.groupby("source_ip"):
            indexed = group.set_index("timestamp")
            
            # Count in preceding window_seconds
            req_cnt = indexed["source_ip"].rolling(f"{self.window_seconds}s").count()
            err_cnt = indexed["is_error"].rolling(f"{self.window_seconds}s").sum()
            
            df.loc[group.index, "ip_req_count_window"] = req_cnt.values
            df.loc[group.index, "ip_error_count_window"] = err_cnt.values

        df["ip_req_count_window"] = df["ip_req_count_window"].fillna(1)
        df["ip_error_count_window"] = df["ip_error_count_window"].fillna(0)
        df["ip_error_rate_window"] = df["ip_error_count_window"] / df["ip_req_count_window"]

        # Restore original order before extracting columns
        df = df.sort_values("_pos")

        # Final feature column selection
        feature_cols = [
            "url_len",
            "url_entropy",
            "suspicious_token_count",
            "is_post",
            "is_error",
            "status_code",
            "is_scanner_ua",
            "ip_req_count_window",
            "ip_error_count_window",
            "ip_error_rate_window",
        ]
        self.feature_names_ = feature_cols
        return df[feature_cols].to_numpy(dtype=np.float32)

    def get_feature_names_out(self, input_features=None) -> List[str]:
        return self.feature_names_
