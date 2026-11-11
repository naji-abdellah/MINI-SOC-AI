# MiniSOC-AI 🛡️🤖

> **A Lightweight, Fully On-Premise, AI-Assisted SOC Pipeline Built for Modest Hardware (8 GB RAM, No GPU, Zero Cloud Budget).**

MiniSOC-AI is an end-to-end security operations and automated triage platform designed to explore how modern detection engineering, machine learning, and local Large Language Models (LLMs) can be integrated responsibly into a Security Operations Center without relying on cloud services, multi-GPU clusters, or blind trust in generative AI.

---

## 🎯 The Core Thesis

Most commercial "AI-driven SOC" solutions rely on expensive cloud platforms (e.g., Microsoft Sentinel + Azure OpenAI) and treat LLM outputs as infallible black boxes.

**MiniSOC-AI proves the alternative:**
1. A complete SIEM + detection + triage workflow can run **100% locally on an 8 GB RAM laptop (Intel i5 10th Gen, CPU-only)**.
2. AI components must be **measured** (precision/recall on labeled datasets, hallucination rates with Promptfoo), **guarded** (strict schema validation + action allow-lists + human approval), and **audited** (tamper-evident SHA-256 hash chains).

---

## 🏗️ Architecture

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
                    Guardrails: Schema Validation + Allow-List
                                        │
                                        ▼
                          Human-in-the-Loop Approval
                                        │
                                        ▼
             Cryptographic Audit Log (SHA-256 Chain) + Streamlit UI
                                        │
                      CI/CD: Tests, Rule Checks, LLM Evals
```

---

## ⚡ Tech Stack & Hardware Constraints

- **Hardware Target:** 8 GB RAM, Intel Core i5 10th Gen (4 cores / 8 threads), No GPU.
- **Operating Environment:** Windows 10/11 with WSL2 (memory capped at 5 GB via `.wslconfig`).
- **Core Languages:** Python 3.12 (optionally Go for high-throughput ingestion).
- **Storage:** [DuckDB](https://duckdb.org/) (vectorized, zero-daemon in-process analytical engine).
- **Vulnerable Targets:** OWASP Juice Shop, DVWA (running in containerized profiles).
- **Detection & ML:** Sigma-style rules, scikit-learn (Isolation Forest), XGBoost.
- **Local AI & Embeddings:** [Ollama](https://ollama.com/) running quantized 3B models (`qwen2.5:3b`, `llama3.2:3b`), local vector retrieval (Chroma / FAISS).
- **Evaluation & Guardrails:** [Promptfoo](https://www.promptfoo.dev/), Pydantic, pytest.
- **Analyst UI:** Streamlit.

---

## 📂 Repository Layout

```
minisoc-ai/
├── README.md               # Project documentation & portfolio guide
├── context.md              # Complete project context, constraints & background
├── docker-compose.yml      # Vulnerable target profiles with strict resource caps
├── .wslconfig.example      # WSL2 RAM discipline configuration template
├── requirements.txt        # Python dependencies
├── docs/
│   ├── architecture.md     # Detailed architecture & data flow diagrams
│   └── learning-notes.md   # Reflective notes following the 5-step learning method
├── ingestion/              # Parsers, normalization, DuckDB loader
├── detections/             # Sigma-style rules & unit test fixtures
│   ├── rules/              # Rule definitions mapped to MITRE ATT&CK
│   └── tests/              # Positive & negative detection tests
├── ml/                     # Feature engineering, Isolation Forest vs XGBoost
├── llm/                    # Prompts, RAG retrieval, Ollama integration, schemas
├── guardrails/             # Schema validation, action allow-list, audit hash chain
├── evals/                  # Promptfoo test suites, hallucination benchmarks
├── dashboard/              # Streamlit analyst dashboard
├── data/                   # Small samples only (bulk/raw data git-ignored)
│   ├── raw/
│   ├── processed/
│   └── samples/
└── .github/workflows/      # Automated CI test and evaluation workflows
```

---

## 🚦 Milestones & Progress

- [x] **Milestone 0: Environment & Repo Setup**
  - Git repository structure, strict `.gitignore`, `.wslconfig.example`, resource-capped `docker-compose.yml`, architecture docs, learning journal.
- [x] **Milestone 1: Logs & Normalization (SIEM Fundamentals)**
  - Schema normalization to ECS/OCSF standard; Apache, Docker JSON, SSH syslog parsers; defensive fallback; DuckDB analytical event store and CLI; break-it tests for out-of-order and hostile logs.
- [x] **Milestone 2: Detection Engineering (Rules & MITRE ATT&CK)**
  - 10 Sigma-style rules mapped to MITRE tactics & techniques; vectorized DuckDB detection engine; automated positive/negative test fixtures; evasion break-it tests defeating URL-encoding and SQL comment obfuscation.
- [ ] **Milestone 3: ML-Based Detection**
  - Feature engineering; Isolation Forest vs XGBoost comparison on labeled attack datasets.
- [ ] **Milestone 4: LLM Triage with RAG**
  - Local Ollama 3B triage pipeline with MITRE technique RAG and prompt injection defenses.
- [ ] **Milestone 5: Guardrails, Evaluation & Auditability**
  - Pydantic schema validation, action allow-lists, Promptfoo hallucination benchmarks, SHA-256 hash chain audit log.
- [ ] **Milestone 6: Dashboard, Feedback Loop & CI**
  - Streamlit analyst interface, analyst feedback loop, GitHub Actions automated CI.

---

## 🚀 Getting Started (Milestone 0)

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

## 🧠 Learning Method

Every milestone is documented in [`docs/learning-notes.md`](docs/learning-notes.md) following a 5-step active retention framework:
1. **Predict:** Formulate a hypothesis before running commands or models.
2. **Build:** Implement the smallest functional iteration.
3. **Break it on purpose:** Execute a dedicated failure experiment to understand boundaries.
4. **Explain it back:** Synthesize what was learned in plain, concise language.
5. **Review:** Re-test understanding after one week.

---

## 👤 Author
**Naji Abdellah** — Engineering Student (Software Engineering & Digitalization), ENSEM Casablanca.
- Focused on AppSec, AI safety, detection engineering, and resilient systems.
