# MiniSOC-AI

> **A Lightweight, Fully On-Premise, AI-Assisted SOC Pipeline Built for Modest Hardware (8 GB RAM, No GPU, Zero Cloud Budget).**

MiniSOC-AI is an end-to-end security operations and automated triage platform designed to explore how modern detection engineering, machine learning, and local Large Language Models (LLMs) can be integrated responsibly into a Security Operations Center without relying on cloud services, multi-GPU clusters, or blind trust in generative AI.

---

## The Core Thesis

Most commercial "AI-driven SOC" solutions rely on expensive cloud platforms (e.g., Microsoft Sentinel + Azure OpenAI) and treat LLM outputs as infallible black boxes.

**MiniSOC-AI proves the alternative:**
1. A complete SIEM + detection + triage workflow can run **100% locally on an 8 GB RAM laptop (Intel i5 10th Gen, CPU-only)**.
2. AI components must be **measured** (precision/recall on temporal splits, hallucination rates with dynamic semantic checks), **guarded** (strict schema validation + deterministic policy floors + action allow-lists + human approval), and **audited** (tamper-evident SHA-256 / HMAC hash chains).

---

## Architecture

```
 Vulnerable Apps (Docker)  ──►  Raw Logs (Web, Auth, System)
        ▲ attacks (Simulated)           │
                                        ▼
                         Ingestion + Normalization (ECS/OCSF)
                                        │
                                        ▼
                              DuckDB (Events Store)
                         ┌──────────────┼───────────────┐
                         ▼              ▼               ▼
                   Sigma Rules     ML Detector    Threat Intel
                  (MITRE ATT&CK) (IF vs XGBoost)     (Feeds)
                         └──────────────┬───────────────┘
                                        ▼
                                  Alerts Store
                                        │
                                        ▼
                 LLM Triage (Ollama 3B + RAG over MITRE & Runbooks)
                                        │
                                        ▼
                    Guardrails: Schema Validation + Policy Floors
                                        │
                                        ▼
                          Human-in-the-Loop Approval
                                        │
                                        ▼
             Cryptographic Audit Log (SHA-256 Chain) + Streamlit UI
                                        │
                      CI/CD: Tests, Rule Checks, Python Evals
```

---

## Tech Stack & Hardware Constraints

- **Hardware Target:** 8 GB RAM, Intel Core i5 10th Gen (4 cores / 8 threads), No GPU.
- **Operating Environment:** Windows 10/11 with WSL2 (memory capped at 5 GB via `.wslconfig`).
- **Core Languages:** Python 3.12 (optionally Go for high-throughput ingestion).
- **Storage:** [DuckDB](https://duckdb.org/) (vectorized, zero-daemon in-process analytical engine).
- **Vulnerable Targets:** OWASP Juice Shop, DVWA (running in containerized profiles).
- **Detection & ML:** Sigma-style rules, scikit-learn (Isolation Forest), XGBoost.
- **Local AI & Embeddings:** [Ollama](https://ollama.com/) running quantized 3B models (`qwen2.5:3b`, `llama3.2:3b`), grounded MITRE & runbook retrieval.
- **Evaluation & Guardrails:** Python-native Evaluation Suite, Pydantic, pytest.
- **Analyst UI:** Streamlit.

---

## Repository Layout

```
minisoc-ai/
├── README.md               # Project documentation & portfolio guide
├── context.md              # Complete project context, constraints & background
├── docker-compose.yml      # Vulnerable target profiles with strict resource caps
├── .wslconfig.example      # WSL2 RAM discipline configuration template
├── requirements.txt        # Python dependencies
├── docs/
│   ├── architecture.md     # Detailed architecture & data flow diagrams
│   ├── ml-evaluation-report.md # ML benchmark & data leakage break-it report
│   └── learning-notes.md   # Reflective notes following the 5-step learning method
├── ingestion/              # Parsers, normalization, DuckDB loader with deterministic event IDs
├── detections/             # Sigma-style rules & unit test fixtures
│   ├── rules/              # Rule definitions mapped to MITRE ATT&CK
│   └── tests/              # Positive & negative detection tests
├── ml/                     # Feature engineering, Isolation Forest vs XGBoost, active learning
├── llm/                    # Prompts, RAG retrieval, Ollama integration, schemas, fallback logger
├── guardrails/             # Schema validation, policy floors, approval gate, HMAC audit hash chain
├── evals/                  # Python-native eval suite, dynamic MITRE semantic checks, test cases
├── dashboard/              # Streamlit analyst dashboard with real-time active learning metrics
├── data/                   # Small samples only (bulk/raw data git-ignored)
│   ├── raw/
│   ├── processed/
│   └── samples/
└── .github/workflows/      # Automated CI test and evaluation workflows
```

---

## Milestones & Progress

- [x] **Milestone 0: Environment & Repo Setup**
  - Git repository structure, strict `.gitignore`, `.wslconfig.example`, resource-capped `docker-compose.yml`, architecture docs, learning journal.
- [x] **Milestone 1: Logs & Normalization (SIEM Fundamentals)**
  - Schema normalization to ECS/OCSF standard; Apache, Docker JSON, SSH syslog parsers with naive UTC preservation; DuckDB analytical event store with deterministic SHA-256 event ID deduplication; break-it tests for out-of-order and hostile logs.
- [x] **Milestone 2: Detection Engineering (Rules & MITRE ATT&CK)**
  - 10 Sigma-style rules mapped to MITRE tactics & techniques (`T1110.001`, `T1190`, `T1595.002`, `T1059`); vectorized DuckDB detection engine; automated positive/negative test fixtures; evasion break-it tests defeating URL-encoding and SQL comment obfuscation.
- [x] **Milestone 3: ML-Based Detection & Active Learning**
  - Feature engineering pipeline (Shannon entropy, lexical tokens, sliding windows); Isolation Forest vs. XGBoost comparative evaluation; data leakage break-it experiment (Temporal vs. Random split); active learning loop calculating empirical validation noise suppression.
- [x] **Milestone 4: LLM Triage with Grounded RAG & Fallback Logging**
  - Local Ollama 3B triage pipeline with MITRE technique & SOC runbook lookup; offline fallback with explicit report tagging; strict JSON schema output; boundary tag quarantine; break-it tests neutralizing direct, multilingual (French), and Base64 prompt injections.
- [x] **Milestone 5: Guardrails, Dynamic Evals & Cryptographic Audit**
  - Pydantic schema validation, deterministic policy layer enforcing severity floors and dismissal restrictions, human approval gate with target entities, SHA-256 / HMAC hash chain sealing metadata and payload, 12/12 dynamic semantic evals.
- [x] **Milestone 6: Dashboard, Feedback Loop & CI**
  - Cyber-themed Streamlit analyst interface, empirical active learning calibration receipts, live DuckDB threat discovery, GitHub Actions automated CI with rule validation, 81 pytest unit tests, and eval checks.

---

## Running the End-to-End Pipeline

MiniSOC-AI is designed to run seamlessly on modest hardware. You can run individual stages or execute the entire pipeline with a single command:

### 1-Command Automated Demo & Attack Simulator (Recommended)
Simulates a multi-stage attack campaign (Reconnaissance, SQLi, SSH Brute Force, OS Command Injection), ingests and enriches with Threat Intelligence, evaluates rules, executes AI triage, records to the cryptographic audit log, and launches the dashboard:
```powershell
# Run automated end-to-end simulation
py scripts/demo.py

# Or run simulation and automatically launch the interactive dashboard:
py scripts/demo.py --dashboard
```

---

### Step-by-Step CLI Execution

#### 1. Ingestion (Normalize Logs to DuckDB with Threat Intel)
```powershell
py -m ingestion.cli --input data/samples/ --db data/minisoc.duckdb
```

#### 2. Detection Engine (Rule Evaluation & MITRE Mapping)
```powershell
py -m detections.cli --rules detections/rules/ --db data/minisoc.duckdb --coverage
```

#### 3. ML Anomaly Detection & Data Leakage Break-It Evaluation
```powershell
py -m ml.evaluate
```

#### 4. LLM Triage with Grounded RAG & Cryptographic Audit
```powershell
py -m llm.cli --db data/minisoc.duckdb
```

#### 5. Automated Evaluation & Semantic Hallucination Benchmark
```powershell
py evals/run_evals.py
```

#### 6. Launch the Interactive SOC Dashboard
```powershell
streamlit run dashboard/app.py
```

#### 7. Run Full Regression Suite (81 Passing Tests)
```powershell
py -m pytest -v
```

---

## 🛠️ Environment Setup & Hardware Discipline

### 1. Windows / WSL2 Memory Setup (Crucial for 8 GB RAM machines)
To prevent WSL2 and Docker from starving your Windows operating system:
```powershell
# Copy the template to your Windows user profile
Copy-Item .wslconfig.example $env:USERPROFILE\.wslconfig

# Restart WSL2 to apply limits (5 GB RAM ceiling, 3 vCPUs)
wsl --shutdown
```

### 2. Python Environment Setup
```powershell
# Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

### 3. Launching Vulnerable Targets (RAM-Disciplined Profiles)
Never start all targets simultaneously. Use Docker Compose profiles:
```bash
# To spin up OWASP Juice Shop only (capped at 512M RAM):
docker compose --profile juiceshop up -d

# To spin up DVWA only (capped at 384M RAM):
docker compose --profile dvwa up -d

# To stop targets:
docker compose down
```

### 4. Running the Test Suite
```bash
pytest -v
```

---

## Learning Method

Every milestone is documented in [`docs/learning-notes.md`](docs/learning-notes.md) following a 5-step active retention framework:
1. **Predict:** Formulate a hypothesis before running commands or models.
2. **Build:** Implement the smallest functional iteration.
3. **Break it on purpose:** Execute a dedicated failure experiment to understand boundaries.
4. **Explain it back:** Synthesize what was learned in plain, concise language.
5. **Review:** Re-test understanding after one week.

---

## Author
**Naji Abdellah** — Engineering Student (Software Engineering & Digitalization), ENSEM Casablanca.
- Focused on AppSec, AI safety, detection engineering, and resilient systems.
