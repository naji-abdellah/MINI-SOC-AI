# Detection Engineering Module

## Purpose
Contains Sigma-style detection rules mapped to MITRE ATT&CK techniques, an execution engine that queries DuckDB, and unit tests validating detection precision and false-positive resilience.

## Roadmap (Milestone 2)
- [ ] Sigma-style rule specification (YAML/JSON).
- [ ] SQL/filter compilation for DuckDB.
- [ ] 8–15 initial detection rules covering:
  - Brute force (T1110)
  - SQL Injection (T1190)
  - Path Traversal (T1083 / T1005)
  - Suspicious User Agents (T1071.001)
  - Command Injection (T1059)
- [ ] Unit tests with positive and negative test cases for each rule.
