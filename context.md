# context.md — Lightweight AI-Assisted SOC (working title: **MiniSOC-AI**)

## 1. Purpose of this file

This file describes my project so that anyone (me, a mentor, or an AI assistant) can understand the goal, constraints, architecture, and learning plan without extra explanation. When asking an AI for help, paste this file first.

## 2. About me (background)

- Naji Abdellah, engineering student (Software Engineering and Digitalization, ENSEM Casablanca), looking for a final-year internship.
- Already worked with: Python, Go, Java, C/C++, PHP, JavaScript; Semgrep, OWASP ZAP, Promptfoo, PentestGPT; GitHub Actions; Docker; XGBoost, Random Forest; Ollama (local LLM) and embeddings; Hyperledger Fabric; Node.js, Spring Boot, React, Streamlit; MySQL, PostgreSQL.
- Previous related work: AI-assisted AppSec pipeline at CIH Bank (correlating tool findings with embeddings and a local LLM, CI/CD security gate); collaborative IDS with XGBoost and Hyperledger Fabric.

## 3. Goals

1. **Learn by building.** Each concept is learned by implementing it, breaking it, and writing down what I learned, so I actually remember it.
2. **Strengthen my resume and portfolio** with one coherent, well-documented, security + AI project.
3. **Inspiration, not imitation.** The idea is inspired by a final-year project report on "SOC Modernization with AI-Driven Detection and Automated Response" (Microsoft Sentinel + Azure OpenAI playbook + Isolation Forest). My project must differ in stack, thesis, data, and evaluation. It is not a copy.

## 4. Hard constraints

- Hardware: laptop/PC with **8 GB RAM, Intel i5 10th gen, no GPU**.
- **No cloud services and no budget.** Only my PC and Wi-Fi.
- Everything must run **locally, open-source, and free**.
- RAM discipline: never run all components at once; limit WSL2 to about 5 GB (`.wslconfig`).

## 5. What the reference project did (for context) and what I do differently

| Reference project | My version |
|---|---|
| Microsoft Sentinel on Azure, deployed with Terraform | Local pipeline: Python/Go ingestion + DuckDB, Docker Compose |
| Azure OpenAI generates tasks, KQL, MITRE explanations | Local small LLM (Ollama, 3B model) with RAG over MITRE ATT&CK and runbooks |
| Isolation Forest on ~11k sign-in logs, no labeled attacks | Labeled attack data; compare unsupervised vs supervised, report precision/recall |
| LLM output not rigorously evaluated | Systematic LLM evaluation (Promptfoo), hallucination checks, human approval gate |
| No audit trail for automated decisions | Tamper-evident hash-chained audit log |
| Future work: dashboards, CI/CD, feedback loops | Included in my scope (Streamlit dashboard, GitHub Actions, analyst feedback) |

**My thesis:** a SOC assistant can run fully on-premise on modest hardware, and its AI components can be measured, guarded, and audited rather than blindly trusted.

## 6. High-level architecture

```
 Vulnerable apps (Docker)  ──►  Logs (web, auth, system)
        ▲ attacks (me)                  │
                                        ▼
                         Ingestion + normalization (Python/Go)
                                        │
                                        ▼
                               DuckDB (events store)
                          ┌─────────────┼───────────────┐
                          ▼             ▼               ▼
                   Sigma-style     ML detector      (later) threat
                   rule engine   (IF vs XGBoost)      intel feeds
                          └─────────────┬───────────────┘
                                        ▼
                                  Alerts table
                                        │
                                        ▼
                  LLM triage (Ollama + RAG over MITRE/runbooks)
                                        │
                                        ▼
              Guardrails: schema validation + human approval
                                        │
                                        ▼
               Hash-chained audit log  +  Streamlit dashboard
                                        │
                       GitHub Actions: tests, rule checks, LLM evals
```

## 7. Tech stack

- **Languages:** Python (main), optionally Go for the ingestion service.
- **Storage:** DuckDB (or SQLite).
- **Targets and attacks:** OWASP Juice Shop / DVWA in Docker; OWASP ZAP, Hydra, sqlmap for attack traffic; public datasets (OTRF Security-Datasets, EVTX-ATTACK-SAMPLES, Splunk attack_data) for extra labeled data.
- **ML:** scikit-learn (Isolation Forest), XGBoost, pandas.
- **LLM:** Ollama with a small quantized model (e.g. Qwen2.5 3B or Llama 3.2 3B) plus a small embedding model; a local vector store (Chroma or FAISS).
- **Evaluation:** Promptfoo, pytest.
- **UI:** Streamlit.
- **DevOps:** Docker Compose, Git/GitHub, GitHub Actions.

## 8. Milestones and concepts to learn

Each milestone ends with a working, committed deliverable and a short "what I learned / what broke" note in the repo.

### Milestone 0 — Environment and repo setup
- **Deliverable:** repo structure, Docker Compose skeleton, `.wslconfig`, README, this context file.
- **Concepts:** Docker and Docker Compose basics, container resource limits, WSL2 memory management, reproducible environments, Git workflow for a solo project.

### Milestone 1 — Logs and normalization (SIEM fundamentals)
- **Deliverable:** vulnerable apps running; attacks executed; logs parsed into one common JSON schema; events stored in DuckDB; basic SQL queries over them.
- **Concepts:**
  - What a SOC is, what a SIEM does, SIEM vs SOAR
  - Log types (web access, authentication, system) and their fields
  - Parsing (regex, structured parsing) and **schema normalization** (e.g. ECS / OCSF ideas)
  - Timestamps and time zones, event ordering
  - Ingestion pipelines, batching vs streaming
  - SQL for log analysis (aggregation, windowing)
- **Break-it exercise:** feed malformed or out-of-order logs and observe what fails.

### Milestone 2 — Detection engineering (rules and MITRE ATT&CK)
- **Deliverable:** 8–15 detection rules (brute force, SQL injection, path traversal, port scan, suspicious user agent, etc.), each mapped to a MITRE ATT&CK technique, with test cases.
- **Concepts:**
  - **MITRE ATT&CK**: tactics, techniques, sub-techniques, how to map an alert
  - **Sigma rules**: format, conversion, writing and testing them
  - Thresholds, time windows, correlation
  - True/false positives and false negatives, **precision, recall, F1**
  - Detection-as-code: versioning and unit-testing rules
- **Break-it exercise:** craft traffic that evades one of my rules, then fix the rule.

### Milestone 3 — ML-based detection
- **Deliverable:** feature engineering pipeline; Isolation Forest vs XGBoost compared on labeled data; evaluation report with metrics and confusion matrices.
- **Concepts:**
  - Feature engineering from logs (rates, counts per window, entropy, rare values)
  - Unsupervised anomaly detection (Isolation Forest) vs supervised classification (XGBoost): when each is appropriate
  - Train/test splits for time-ordered data, **data leakage**
  - Imbalanced classes, precision-recall curves, threshold tuning
  - Concept drift and retraining schedules
  - Why a single "false positive rate" number can mislead
- **Break-it exercise:** change the attack mix between train and test and observe the metrics collapse.

### Milestone 4 — LLM triage with RAG
- **Deliverable:** for each alert, the local LLM produces a structured JSON triage (summary, likely ATT&CK technique, severity, suggested next steps), grounded in retrieved MITRE and runbook text.
- **Concepts:**
  - How LLMs work at the level needed: tokens, context window, temperature
  - Running quantized models on CPU (trade-offs of size, speed, quality)
  - **Embeddings** and similarity search; vector stores
  - **RAG** pipeline: chunking, retrieval, prompt assembly
  - Prompt design and **structured output** (JSON schemas)
  - Prompt injection via log content (attacker-controlled text inside logs)
- **Break-it exercise:** inject a malicious instruction inside a log line and see whether the LLM obeys it.

### Milestone 5 — Guardrails, evaluation, and auditability
- **Deliverable:** schema validation of LLM output; allow-list of permitted response actions; human-approval step; Promptfoo test suite measuring correctness and hallucination rate; hash-chained audit log of every alert, LLM output, and decision.
- **Concepts:**
  - LLM evaluation: test sets, rubrics, regression testing for prompts
  - Hallucination types and how to detect them (e.g. invented ATT&CK IDs, wrong commands)
  - Guardrails: validation, allow-lists, least privilege for automation
  - Human-in-the-loop design
  - **Hash chains** and tamper evidence (relation to blockchain ideas, without the overhead)
  - Basic OWASP Top 10 for LLM Applications
- **Break-it exercise:** modify one audit record and confirm the verification script detects it.

### Milestone 6 — Dashboard, feedback loop, and CI
- **Deliverable:** Streamlit dashboard (alert volume, ATT&CK coverage, detector metrics, pending approvals); analyst feedback stored and used to improve prompts or thresholds; GitHub Actions running tests, rule checks, and LLM evals on every push.
- **Concepts:**
  - SOC metrics: MTTD, MTTR, alert volume, alert fatigue, coverage
  - Data visualization for analysts
  - Feedback loops and continuous improvement
  - CI/CD for detection rules and ML/LLM components
  - Reproducible evaluation in CI (fixed seeds, small test sets)

### Optional extensions
- Ingest a second log source (e.g. Windows EVTX samples) and extend detections.
- Threat-intelligence enrichment from free feeds (e.g. IP reputation lists).
- Compare two or more small LLMs on the same evaluation set (quality vs latency vs RAM).
- Go rewrite of the ingestion service for performance comparison.

## 9. Learning method (how I make concepts stick)

For every milestone:
1. **Predict:** write down what I expect before running anything.
2. **Build:** implement the smallest working version.
3. **Break it on purpose:** do the "break-it exercise" and record the result.
4. **Explain it back:** write 5–10 lines in `docs/learning-notes.md` in my own words (what the concept is, what surprised me, what failed).
5. **Review after a week:** re-read the notes and answer a few questions from memory.

## 10. Repository layout (planned)

```
minisoc-ai/
├── README.md
├── context.md
├── docker-compose.yml
├── docs/
│   ├── learning-notes.md
│   └── architecture.md
├── ingestion/        # parsers, normalization, DuckDB loader
├── detections/       # Sigma-style rules + tests
├── ml/               # features, training, evaluation notebooks/scripts
├── llm/              # prompts, RAG, Ollama client, schemas
├── guardrails/       # validation, allow-list, approval, audit log
├── evals/            # Promptfoo configs, test sets
├── dashboard/        # Streamlit app
├── data/             # small samples only (no large files in git)
└── .github/workflows/
```

## 11. Success criteria

- Entire system runs on an 8 GB RAM machine with no GPU and no cloud.
- At least 8 detection rules mapped to MITRE ATT&CK, each with tests.
- ML comparison reported with precision, recall, and F1, including an honest discussion of limitations.
- LLM triage evaluated with a documented test set and a measured hallucination rate.
- Every automated suggestion passes validation and human approval, and is recorded in a verifiable audit log.
- A clear README with architecture diagram, demo screenshots or GIF, and lessons learned, so the repo works as a portfolio piece and as a talking point in internship interviews.

## 12. Honest risks

- Small CPU-only LLMs are slow and less accurate: keep prompts short, outputs structured, and report quality honestly.
- Public datasets may not match my own logs: document the differences instead of hiding them.
- Scope creep: finish each milestone's deliverable before starting the next; optional extensions come last.
