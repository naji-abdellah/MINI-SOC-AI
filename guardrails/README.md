# Guardrails, Governance & Audit Module

## Purpose
Enforces defense-in-depth on LLM outputs:
1. Strict schema validation (Pydantic).
2. Action allow-list policy enforcement (disallowing unauthorized commands).
3. Human-in-the-loop analyst approval.
4. Tamper-evident cryptographic hash chain recording all alerts, triage decisions, and analyst approvals.

## Roadmap (Milestone 5)
- [ ] Pydantic output validators.
- [ ] Policy allow-list engine.
- [ ] Interactive approval gate.
- [ ] SHA-256 hash-chained JSONL audit log implementation and verification script.
- [ ] Audit tampering break-it test.
