# Detection Engineering Module

## Purpose
Contains Sigma-style detection rules mapped to MITRE ATT&CK techniques, an execution engine that queries DuckDB, and unit tests validating detection precision and false-positive resilience.

## Implementation Status (Milestone 2)
- [x] Sigma-style rule specification (JSON format with MITRE technique mapping).
- [x] Vectorized SQL/filter compilation for DuckDB (`engine.py`).
- [x] 10 initial detection rules covering:
  - Brute force (T1110.001)
  - SQL Injection (T1190)
  - Path Traversal (T1083 / T1005)
  - Suspicious User Agents & Scanners (T1595.002)
  - Command Injection (T1059)
- [x] Unit tests with positive, negative, and evasion break-it test cases for each rule (`tests/test_detections.py`, `tests/test_detection_evasion.py`).
