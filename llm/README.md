# LLM Triage & RAG Module

## Purpose
Interacts with a local quantized model (Ollama `qwen2.5:3b` or `llama3.2:3b`) to triage detected alerts, enriched with retrieved context from MITRE ATT&CK techniques and incident response runbooks.

## Roadmap (Milestone 4)
- [ ] Ollama local client integration.
- [ ] Vector store indexing (MITRE ATT&CK descriptions + SOC runbooks).
- [ ] Context-augmented prompt construction with strict JSON output schemas.
- [ ] Adversarial prompt injection defense experiments.
