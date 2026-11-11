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

### 1. Predict
- **Question:** How do heterogeneous logs (Apache web access, Docker stdout JSON, Linux syslog auth) map into a unified schema? What happens when logs arrive out of chronological order or contain malformed timestamps?
- **Hypothesis:** 
  1. A unified schema (ECS/OCSF) can capture web, auth, and system logs under standard keys (`@timestamp`, `source_ip`, `event_category`, `event_outcome`).
  2. Ingesting out-of-order logs will not corrupt SIEM analytics because relational/columnar stores sort temporally via index-backed `ORDER BY timestamp` rather than physical insertion order.
  3. Corrupted or hostile logs might cause unhandled parser exceptions or silent timestamp corruption if not defensively handled.

### 2. Build
- **Unified Normalized Schema (`ingestion/schema.py`):** Pydantic-based schema inspired by Elastic Common Schema (ECS) and Open Cybersecurity Schema Framework (OCSF). Automatically normalizes all timestamps to UTC ISO-8601 and capitalizes HTTP methods.
- **Specialized Parsers (`ingestion/parsers/`):**
  - `web_parser.py`: Apache/Nginx Combined log format (extracts IP, user, method, URL, status code, outcome, user agent).
  - `json_parser.py`: Docker container stdout wrapper format (Juice Shop) and structured JSON logs.
  - `auth_parser.py`: Linux syslog / SSH authentication failure and success lines.
- **Defensive Dispatcher (`ingestion/dispatcher.py`):** Automatically routes raw lines to the appropriate parser; catches malformed/unmatched lines into a safe fallback tier with `tags=["unparsed", "malformed_candidate"]` to guarantee zero forensic evidence loss.
- **DuckDB Events Store (`ingestion/duckdb_store.py`):** Fast columnar in-process analytical store with schema indexes and SIEM queries (`get_top_source_ips`, `get_failed_logins_by_ip`, `get_http_error_distribution`).
- **CLI (`ingestion/cli.py`):** Batch ingestion CLI providing real-time SIEM overview statistics.
- **Test Suite:** 9 unit and break-it tests covering parsers, timezones, scrambled order, and malformed inputs.

### 3. Break it on Purpose
- **Exercise 1: Feeding Scrambled/Out-of-Order Logs:**
  - Ingested events in reverse chronological order ($T_3 \rightarrow T_1 \rightarrow T_2$). Verified that DuckDB analytical queries restore exact temporal sequence using `ORDER BY timestamp ASC`.
- **Exercise 2: Malformed & Hostile Log Lines (`data/samples/malformed.log`):**
  - Tested corrupted timestamps (`99/99/9999`), truncated lines, non-numeric HTTP statuses, unclosed JSON, and raw noise.
  - *Key Discovery & Fix:* Initially, `web_parser` caught `date_parser.parse` errors and silently defaulted to `datetime.now(utc)`. This was dangerous: it fabricated timestamps for corrupted logs, destroying forensic timeline integrity. Fixed the parser to reject corrupted lines, allowing the dispatcher to preserve the raw line verbatim tagged as `malformed_candidate`.
- **Exercise 3: Credential Stuffing vs. Username Spraying:**
  - Initial query grouped failed logins by `(source_ip, user_name)`. When testing an SSH brute force log where the attacker sprayed 5 different usernames from the same IP (`root`, `admin`, `oracle`, `postgres`, `test`), the alert failed to trigger because each username only had 1 failure.
  - *Fix:* Grouped by `source_ip` and aggregated `string_agg(DISTINCT user_name, ', ')` so that both single-user brute force and multi-user credential spraying are caught.
- **Exercise 4: Python & DuckDB Environment Gotchas:**
  - DuckDB requires `pytz` when fetching `TIMESTAMPTZ` columns as Python objects.
  - Windows PowerShell console default encoding (`cp1252`) choked on emoji characters in CLI print statements; refactored CLI output to clean ASCII.

### 4. Explain it Back
- **SIEM vs. Normalization:** A SIEM is only as good as its normalization layer. Raw logs are messy and inconsistent across vendors. Schema normalization (ECS/OCSF) creates a common taxonomy: detection rules don't need to know whether an event came from Nginx, Apache, or Node.js—they only inspect `source.ip`, `http.request.url`, and `event.outcome`.
- **Evidence Preservation:** In security engineering, an unparseable log line must never be dropped or silently modified. It must be preserved verbatim in raw storage with an audit tag (`malformed_candidate`) so analysts can investigate whether an attacker attempted parser evasion.
- **DuckDB for Low-Spec SIEM:** DuckDB delivers columnar vectorized querying without requiring a heavy Elasticsearch or JVM daemon. It runs in-process, consumes virtually zero idle RAM, and processes analytical queries in milliseconds, ideal for an 8 GB RAM laptop.

### 5. Review (Scheduled)
- [ ] Benchmark DuckDB ingestion throughput on 10,000+ events.
- [ ] Measure memory footprint during bulk imports.
