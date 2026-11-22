# Guardrails, Governance & Audit Module

## Purpose
Enforces defense-in-depth on LLM outputs:
1. Strict schema validation (Pydantic).
2. Action allow-list policy enforcement (disallowing unauthorized commands).
3. Human-in-the-loop analyst approval.
4. Tamper-evident cryptographic hash chain recording all alerts, triage decisions, and analyst approvals.

## Implementation Status (Milestone 5)
- [x] Pydantic output validators with hardened bounds checking.
- [x] Policy allow-list engine with severity floors and dismissal restrictions (`guardrails/policy.py`).
- [x] Interactive approval gate with strict state lifecycle and target entity specification (`guardrails/approval.py`).
- [x] SHA-256 / HMAC hash-chained JSONL audit log sealing `entry_id`, `entry_type`, `timestamp`, `prev_hash`, and payload (`guardrails/audit_log.py`).
- [x] Fast tail reading and metadata tamper detection break-it tests (`tests/test_audit_log.py`).
