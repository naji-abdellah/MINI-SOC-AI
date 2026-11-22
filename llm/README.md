# LLM Triage & RAG Module

## Purpose
Interacts with a local quantized model (Ollama `qwen2.5:3b` or `llama3.2:3b`) to triage detected alerts, enriched with retrieved context from MITRE ATT&CK techniques and incident response runbooks.

## Implementation Status (Milestone 4)
- [x] Ollama local client integration with cached availability checks and fallback logging (`client.py`).
- [x] Grounded retrieval over MITRE ATT&CK enterprise techniques and SOC incident response runbooks (`rag.py`).
- [x] Context-augmented prompt construction with quarantine boundary tags and Pydantic JSON output validation (`prompts.py`, `schemas.py`).
- [x] Adversarial prompt injection defense experiments: direct, multilingual (French), Base64 evasion, and deterministic policy defense-in-depth (`tests/test_prompt_injection.py`).
