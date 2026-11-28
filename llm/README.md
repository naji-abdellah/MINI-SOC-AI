# LLM Triage & Grounded Retrieval Module

## Purpose
Interacts with a local quantized model (Ollama `qwen2.5:3b` or `llama3.2:3b`) to triage detected alerts, enriched with retrieved context from MITRE ATT&CK techniques and incident response runbooks.

## Grounded Lookup Architecture
MiniSOC-AI uses a fast, deterministic in-memory grounded retrieval engine (`llm/rag/retriever.py`) indexing MITRE ATT&CK techniques (`mitre_attack.json`) and standard SOC operating runbooks (`soc_runbooks.json`). This provides sub-millisecond context retrieval with zero external vector database daemon overhead (no ChromaDB or network services required).

## Implementation Status
- [x] Ollama local client integration with cached availability checks, offline fallback mode with explicit tagging (`source="offline_fallback"`), and offline triage boundary inspection (`client.py`).
- [x] Grounded retrieval over MITRE ATT&CK enterprise techniques and SOC incident response runbooks (`llm/rag/retriever.py`).
- [x] Context-augmented prompt construction with XML boundary tag encapsulation (`<untrusted_event_evidence>`), tag stripping/sanitization, and attacker-controlled entity quarantine (`source_ip`, `target_user`) (`prompts.py`, `schemas.py`).
- [x] Adversarial prompt injection defense experiments: direct injection, XML tag breakout attempts, attacker-controlled username injections, multilingual (French), Base64 evasion, and deterministic policy defense-in-depth (`tests/test_prompt_injection.py`).
- [x] Offline test isolation: Unit tests force `OLLAMA_OFFLINE_MODE=true` to prevent test flakiness, while real-model runs are gated behind `@pytest.mark.ollama`.
