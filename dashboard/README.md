# Analyst Dashboard Module

## Purpose
A lightweight Streamlit web application providing:
- Alert volume and severity distributions.
- MITRE ATT&CK coverage visualization.
- Interactive triage approval queue with LLM reasoning and retrieved context.
- Audit log tamper verification panel.

## Implementation Status (Milestone 6)
- [x] Streamlit application layout (`app.py`) with modern cyber/dark aesthetics.
- [x] DuckDB query connectors for real-time visualization (`data.py`).
- [x] Interactive human-in-the-loop approval queue with SOAR CLI containment integration.
- [x] Tamper-evident SHA-256 audit log cryptographic chain verification panel.
- [x] Analyst active learning feedback collection interface with empirical threshold calibration.
