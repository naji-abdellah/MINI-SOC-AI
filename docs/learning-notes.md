# MiniSOC-AI — Learning Notes

This document captures reflections, surprises, breaking experiments, and key insights for each milestone, following the 5-step learning method:
1. **Predict:** Anticipate outcomes before running commands or code.
2. **Build:** Implement the minimal viable deliverable.
3. **Break it on purpose:** Run the milestone break-it exercise and document failure modes.
4. **Explain it back:** Summarize the core concept in plain words.
5. **Review:** Revisit after a week to reinforce retention.

---

## Milestone 0: Environment and Repo Setup

### 1. Predict
- **Question:** What happens if WSL2 runs without memory limits on an 8 GB RAM laptop while running Docker, an IDE, and a browser?
- **Hypothesis:** Windows host memory will be starved as WSL2's Vmmem process balloons to consume available RAM (up to 50% or 80%), causing severe swapping, UI freezing, or container crashes.

### 2. Build
- Initialized Git repository with clean `.gitignore`.
- Created `.wslconfig.example` allocating a strict 5 GB ceiling and 3 vCPUs to WSL2.
- Configured `docker-compose.yml` with container resource constraints (Juice Shop 512M, DVWA 384M) and Docker Compose profiles to prevent concurrent execution.
- Laid out modular project structure separating ingestion, detection, ML, LLM triage, guardrails, evaluation, and dashboard.

### 3. Break it on Purpose
- **Exercise:** Inspect container resource enforcement and memory caps. Verify what happens when memory limits are exceeded or missing.
- **Result & Observation:** Setting `deploy.resources.limits.memory` in Docker Compose prevents rogue containers from taking down the host operating system. Without `.wslconfig`, WSL2 defaults to taking up to 50% of total host RAM by default on Windows 10/11, leaving Windows host with insufficient room when Ollama is running natively on Windows.

### 4. Explain it Back
- **WSL2 Memory Management:** WSL2 is a lightweight Hyper-V virtual machine. Unlike traditional VMs with fixed memory allocations, WSL2 dynamically requests memory from the host and does not readily return freed pages unless configured (`autoMemoryReclaim=gradual` or explicitly capped in `%USERPROFILE%\.wslconfig`).
- **Resource Discipline for Low-Spec AI:** On an 8 GB RAM machine, running an OS (Windows ~2.5 GB), an IDE + Browser (~2 GB), a local 3B LLM in Ollama (~2 GB), and Docker containers requires strict orchestration: services must be isolated into on-demand profiles rather than running continuously.

### 5. Review (Scheduled)
- [ ] Confirm `.wslconfig` is applied in `%USERPROFILE%` and verified via `wsl --status`.
- [ ] Check Docker memory allocation with `docker stats`.

---

## Milestone 1: Logs and Normalization (SIEM Fundamentals)
*(To be completed during Milestone 1)*

### 1. Predict
-

### 2. Build
-

### 3. Break it on Purpose
-

### 4. Explain it Back
-

### 5. Review
-
