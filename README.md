---
title: Security Vulnerability Scanner
emoji: 🔒
colorFrom: blue
colorTo: red
sdk: docker
pinned: true
tags:
  - openenv
  - security
  - reinforcement-learning
  - code-review
  - vulnerability-detection
  - llm-evaluation
short_description: "OpenEnv security audit: 3 tasks, RL agents, graded 0-1."
---

# Security Vulnerability Scanner

An AI agent environment for automated security code review and vulnerability detection. Built as an [OpenEnv](https://openenv.dev)-compatible reinforcement learning environment where agents analyze Python codebases to find planted security vulnerabilities across 3 tasks of increasing difficulty.

## Why This Matters

Security code review is the last line of defense before vulnerabilities reach production. It requires deep expertise, is time-consuming, and is error-prone under deadline pressure. A single missed SQL injection or hardcoded secret can lead to a full data breach.

This environment trains AI agents to do what a junior security engineer does on their first week of a code audit: read unfamiliar code, recognize dangerous patterns, report them with precision, and suggest concrete fixes — all under step constraints that mirror real audit time pressure.

**Real-world relevance:**
- The 15 vulnerability types are the OWASP Top 10 plus common Python-specific patterns
- Each task is modeled on a real class of production codebases: internal scripts, Flask apps, and SaaS REST APIs
- The scoring function rewards specificity of remediation — not just "use parameterized queries" but which library, which call, at which line
- Attack chains reward agents that reason about how vulnerabilities compound (e.g., insecure deserialization + path traversal = full RCE without needing either alone)

## Environment Description

The environment simulates a realistic security audit scenario where an agent receives source code files, analyzes them for vulnerabilities, and reports findings with exact details. Three tasks cover progressively harder scenarios — from a single-file module to a full SaaS platform API with hidden files and cascading attack chains.

## Observation Space

Each step returns an `Observation` object with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `files` | `dict[str, str]` | Filename to full source code of currently visible files |
| `current_findings` | `list[Finding]` | All vulnerabilities reported so far this episode |
| `step_number` | `int` | Current step count |
| `task_id` | `int` | Active task identifier (1, 2, or 3) |
| `feedback` | `str` | Result of the last action taken |
| `remaining_steps` | `int` | Steps remaining before episode auto-terminates |
| `active_insights` | `list[str]` | Cascading insights unlocked by true positive findings |
| `suspicious_files` | `list[str]` | Files flagged as high-priority by the environment |

Each `Finding` contains: `file`, `line_number`, `vulnerability_type`, `severity`, `description`, `suggested_fix`.

## Action Space

The agent can take one of 4 discrete actions per step:

| Action | Parameters | Description |
|--------|-----------|-------------|
| `report_vulnerability` | `file`, `line_number`, `vulnerability_type`, `severity`, `description`, `suggested_fix` (+ optional: `function`, `data_flow_source`, `sink`, `exploitability_reason`) | Report a found vulnerability with type, exact line, severity, and fix. Optional evidence fields are required only when evidence mode is enabled. |
| `request_file` | `filename` | Request to see a hidden file not initially visible |
| `mark_complete` | *(none)* | Signal that the security scan is complete |
| `add_note` | `note` | Add a reasoning note (contributes to scoring in Task 3) |

## Task Descriptions

| Task | Name | Difficulty | Files | Vulnerabilities | Max Steps | Target Score |
|------|------|-----------|-------|-----------------|-----------|-------------|
| 1 | Single File Audit | Easy | 1 | 3 | 10 | 0.90+ |
| 2 | Multi-File Flask App | Medium | 4 (2 hidden) | 5 | 20 | 0.80+ |
| 3 | Real-World Project Audit | Hard | 5 (all revealed at reset) | 7 | 40 | 0.75+ |

### Task 1 — Single File Audit (Easy)
Analyze a single Python module (user management backend) with a database manager and data processor. All 3 vulnerabilities are in one file that is fully visible from the start. Designed to verify basic pattern recognition.

### Task 2 — Multi-File Flask App (Medium)
Audit a Flask-based file manager application with user accounts and an admin panel. The app has 4 source files — only 2 are initially visible. The agent must use `request_file` to reveal hidden files. Static analysis hints are prepended to revealed files to simulate a real SAST tool assist.

### Task 3 — Real-World Project Audit (Hard)
Audit a production-style SaaS platform REST API with authentication, webhooks, XML parsing, and user management. All 5 source files are revealed at reset — the challenge is not discovery but analysis depth. Severity accuracy scoring is enabled, reasoning notes contribute bonus points, and attack chain bonuses reward agents that identify how vulnerabilities compound.

## Reward Function

| Signal | Condition | Value |
|--------|-----------|-------|
| Type match | Vulnerability type matches ground truth (fuzzy) | +0.3 |
| Line bonus | Line number within ±3 of ground truth | +0.1 |
| Fix quality | Suggested fix contains security-relevant keywords | +0.1 |
| Severity match | Severity matches ground truth (Task 3 only) | +0.1 |
| False positive | Reported vulnerability not in ground truth | -0.1 |
| Duplicate | Same (file + type) reported twice | -0.05 |
| Notes bonus | Security reasoning notes submitted (Task 3 only) | +0.05 (episode) |
| Early completion | Finished in ≤50% steps with 100% detection rate | +0.05 (episode) |

**Episode score formula:**
```
max_per_finding = 0.5 (Tasks 1-2) or 0.6 (Task 3)
max_possible = num_vulnerabilities × max_per_finding
raw_score = sum(max(0, step_reward) for each true positive)
final_score = clamp(raw_score / max_possible, 0.0, 1.0)
```

## Vulnerability Types

The environment recognizes 15 vulnerability types spanning OWASP Top 10 and Python-specific patterns:

| # | Type | Common Pattern | Severity |
|---|------|----------------|---------|
| 1 | SQL Injection | f-string or %s in SQL query | Critical |
| 2 | Hardcoded Secret | API key as string literal | High |
| 3 | Command Injection | `eval()` on user input | Critical |
| 4 | Path Traversal | `os.path.join` with user input | High |
| 5 | Insecure Deserialization | `pickle.loads()` on user data | Critical |
| 6 | Broken Authentication | Route with no auth check | High |
| 7 | Weak Cryptography | MD5/SHA1 for password hashing | High |
| 8 | SSRF | `requests.get(user_url)` unvalidated | High |
| 9 | XXE Injection | `ET.parse()` on user input | High |
| 10 | IDOR | DB fetch by ID with no ownership check | High |
| 11 | Mass Assignment | `Model(**request.json())` | Medium |
| 12 | Timing Attack | `==` comparison on tokens | Medium |
| 13 | CORS Misconfiguration | `origins="*"` with credentials | Medium |
| 14 | Debug Mode | `DEBUG = True` in production | Medium |
| 15 | JWT Misconfiguration | Hardcoded JWT secret string | Critical |

## Attack Chains

The environment models 5 multi-vulnerability exploit chains. Agents that identify all components of a chain receive a bonus, rewarding reasoning about how vulnerabilities compound:

| Chain | Vulnerabilities | Bonus | Impact |
|-------|----------------|-------|--------|
| Full RCE | Path Traversal + Insecure Deserialization | +0.06 | Attacker writes malicious pickle, triggers load |
| Cross-Origin Admin Takeover | CORS Misconfiguration + Broken Authentication | +0.05 | Any site makes authenticated admin requests |
| Complete Account Takeover | JWT Misconfiguration + Timing Attack + IDOR | +0.08 | Forge token → enumerate valid → access any account |
| Privilege Escalation | IDOR + Mass Assignment | +0.05 | Access any account → escalate their role |
| Debug-Amplified XXE | Debug Mode + XXE Injection | +0.04 | XXE reads server files → debug exposes them in stack traces |

## Cascading Insight System

When an agent finds a true positive, the environment unlocks contextual insights pointing to related vulnerabilities. This simulates how a real security engineer thinks:

```
Agent reports: Path Traversal in app.py  ✓
Environment reveals: "Path traversal in app.py — session handler in utils.py
  uses same input flow. Check how cookies reach filesystem."
→ suspicious_files: ["utils.py"]

Agent reports: Insecure Deserialization in utils.py  ✓
Environment reveals: "Pickle + path traversal = full RCE chain.
  Attacker writes malicious pickle then triggers load."
→ Attack chain bonus unlocked: Full RCE (+0.06)
```

## Example Agent Trajectory

Below is a sample interaction showing the structured workflow an optimal agent follows on Task 3:

```
Step 1  | add_note       | "Starting Task 3. Files: config.py, auth.py, views.py,
          |                | serializers.py, middleware.py. Will scan all before reporting."
Step 2  | report_vulnerability | config.py:10  JWT Misconfiguration  Critical  +0.40
          | → INSIGHT: "Hardcoded JWT secret = any token forgeable. Check auth.py verify_token()"
          | → suspicious_files: ["auth.py"]
Step 3  | report_vulnerability | config.py:6   Debug Mode            Medium    +0.30
          | → INSIGHT: "DEBUG=True exposes stack traces. Any injection becomes RCE via debug console."
Step 4  | report_vulnerability | auth.py:34    Timing Attack         Medium    +0.30
          | → INSIGHT: "== comparison + forged JWT = attacker can enumerate valid tokens. Check views.py"
Step 5  | report_vulnerability | views.py:28   SSRF                  High      +0.40
Step 6  | report_vulnerability | views.py:67   IDOR                  High      +0.40
Step 7  | report_vulnerability | serializers.py:19  Mass Assignment  Medium    +0.30
Step 8  | report_vulnerability | middleware.py:41   XXE Injection    High      +0.40
Step 9  | add_note       | "JWT + Timing Attack + IDOR forms complete account takeover chain."
Step 10 | mark_complete  | Score: 1.000 (7/7 found, 0 FP, chain bonus: +0.08, early bonus: +0.1)
```

**Key behaviors:** reads all files first → reports critical before medium → uses insights → documents chain reasoning → completes in 10/40 steps for early bonus.

## Baseline Scores

### LLM Agent (Llama 3.1 70B via NVIDIA NIM) — latest measured run

Values below match `inference_results.json` from a full local run (same commit as submission).

| Task | Score | Findings | False Positives | Steps Used | Triage Score |
|------|-------|----------|-----------------|------------|--------------|
| Task 1 (Easy) | 1.000 | 3/3 | 0 | 5 | — |
| Task 2 (Medium) | 1.000 | 5/5 | 0 | 8 | 0.700 |
| Task 3 (Hard) | 0.935 | 7/7 | 1 | 13 | 0.679 |
| **Overall** | **0.978** | — | — | — | — |

Wall time for that run: **~6m 21s** (under the **20 minute** hackathon inference cap).

### Rule-Based Deterministic Baseline (no LLM, zero API calls)

The environment ships with a deterministic regex scanner to prove discriminability — a pattern-matching script that costs zero API calls but scores significantly lower than the LLM:

| Task | Score | Notes |
|------|-------|-------|
| Task 1 | 1.000 | Matches all easy-task findings |
| Task 2 | 0.440 | Captures subset of true patterns; misses several chain-linked signals |
| Task 3 | 0.759 | Better coverage than Task 2, but weaker precision than LLM |
| **Overall** | **0.733** | |

**Gap of +0.245** (LLM 0.978 vs deterministic 0.733) demonstrates the environment still rewards stronger reasoning and trajectory control, especially on medium/hard tasks.

Sampling used for this run: `temperature=0.0`, `top_p=1.0`, `max_tokens=1500`, `OPENAI_SEED=42`, `REPRODUCIBLE_MODE=true`.

Results above were produced with trap/precision/anti-gaming settings enabled in `environment/config.py` during evaluation.

## Hackathon pre-submission checklist

Phase 1 gates from the organizer brief, and how this repository addresses them:

| Requirement | Status in this repo |
|-------------|---------------------|
| **HF Space deploys** | Docker Space builds from root `Dockerfile`; app listens on **7860**. |
| **Ping Space → HTTP 200 + `reset()`** | `POST /reset` with `{}` or `{"task_id": <1, 2, or 3>}` returns **200** (default `task_id=1` when body is empty). |
| **OpenEnv spec** | `openenv.yaml`, Pydantic models, `GET /state`, `POST /reset`, `POST /step`, `GET /validate`. Run `uv run openenv validate`. |
| **Dockerfile builds** | `docker build -t security-scanner .` from repo root. |
| **Baseline / inference completes** | Root `inference.py` runs deterministic baseline then LLM on tasks 1–3; writes `inference_results.json`. |
| **3+ tasks, graders, scores in [0,1]** | Tasks 1–3 with graders; episode scores clamped to **[0, 1]**. |
| **Mandatory env vars** | Set **`HF_TOKEN`**, **`API_BASE_URL`**, **`MODEL_NAME`** on the runner (HF Space secrets or `.env`). **`ENV_BASE_URL`** must point at the live environment (e.g. Space URL or `http://localhost:7860`). |
| **OpenAI client for all LLM calls** | `from openai import OpenAI` — all completions go through `client.chat.completions.create`. |
| **Structured stdout** | For each LLM task: **`[START]`** → one **`[STEP]`** per `POST /step` → **`[END]`** (see `inference.py`). Human-readable traces use **stderr**; capture **stdout only** to audit protocol lines (e.g. Windows: `python inference.py 2>NUL`). |
| **Runtime &lt; 20 min; 2 vCPU / 8 GB** | Full run measured **~6–7 min** locally; keep `MAX_TOKENS` and timeouts conservative on small instances. |
| **Validator script** | `scripts/validate-submission.sh <space_url> [repo_dir]` (bash: Git Bash / WSL). |

### Sample inference script vs this project

The official sample uses **asyncio** and **`from_docker_image(IMAGE_NAME)`** to drive the environment in-process. This submission uses the **same OpenEnv contract over HTTP** (`httpx` to `ENV_BASE_URL`), which matches a **FastAPI + Docker Space** deployment. Optional **`LOCAL_IMAGE_NAME` / `IMAGE_NAME`** is read for spec parity but not required for the HTTP path.

### Reproduce the reported baseline exactly

1. **Python 3.11+**, install deps: `pip install -r requirements.txt` (or `uv sync` if you use `uv`).
2. **Repo root `.env`** (mirror what you set on HF; example that produced the table above):

```env
HF_TOKEN=<your_nvidia_or_hf_api_key>
API_BASE_URL=https://integrate.api.nvidia.com/v1
MODEL_NAME=meta/llama-3.1-70b-instruct
ENV_BASE_URL=http://localhost:7860
OPENAI_SEED=42
REPRODUCIBLE_MODE=true
TEMPERATURE=0.0
TOP_P=1.0
MAX_TOKENS=1500
```

3. **Validate**: `uv run openenv validate` (from repo root).
4. **Terminal A — environment**: `uvicorn main:app --host 0.0.0.0 --port 7860`
5. **Terminal B — inference**: `python inference.py`  
   - Optional: `python inference.py 2>NUL` (Windows) or `2>/dev/null` (Unix) to list **only** `[START]` / `[STEP]` / `[END]` on stdout.
6. **Artifacts**: `inference_results.json` (includes `submission_config` + `reproducibility` blocks for auditing).
7. **Docker**: `docker build -t security-scanner .` then `docker run -p 7860:7860 security-scanner` for a container-only server smoke test.

Scores are **stochastic** to a degree (provider + model); same env vars and seed maximize repeatability. For HF judging, define **`API_BASE_URL`**, **`MODEL_NAME`**, and **`HF_TOKEN`** in the Space or CI **secrets**, and set **`ENV_BASE_URL`** to the **public Space URL** when inference runs outside the container.

## Active Feature Flags (Current Project Setup)

Current run mode in `environment/config.py`:

- `ENABLE_EVIDENCE_MODE = False`
- `ENABLE_ADVERSARIAL_TRAPS = True`
- `ENABLE_PRECISION_SCORING = True`
- `ENABLE_ANTI_GAMING_ESCALATION = True`

What this means:
- Adversarial safe-but-suspicious traps are active.
- Precision-aware episode scoring is active.
- Escalating false-positive penalties are active.
- Strict evidence-required mode is currently disabled.

## Trap-Aware Enhancements

The environment includes intentional safe decoys to penalize weak pattern matching:

- **Easy (Task 1):** safe SHA-256/helper comparison patterns.
- **Medium (Task 2):** fixed allowlisted request + safe HMAC helper patterns.
- **Hard (Task 3):** safe signature/helper code paths around auth/middleware.

Inference includes deterministic trap interception in `inference.py` to reduce avoidable false positives before an action is sent.

## Agent Failure Modes

This section documents where agents fail and why — a signal that this is a research-quality environment that discriminates agent capability levels.

### Failure Mode 1 — Premature Completion
**Symptom:** Agent calls `mark_complete` after finding 3–4 vulnerabilities on Task 3.
**Cause:** LLM treats the first plausible set of findings as complete; no internal count check.
**Environment response:** `mark_complete` interceptor blocks early completion and injects file-specific hints.
**Why it's hard:** Task 3 has 7 vulnerabilities across 5 files — agents must maintain a mental checklist across a long context window.

### Failure Mode 2 — Type Confusion
**Symptom:** Agent reports `Hardcoded Secret` for a JWT secret (should be `JWT Misconfiguration`), or `Weak Cryptography` for a timing attack (should be `Timing Attack`).
**Cause:** Both pairs are semantically similar but require domain-specific knowledge to distinguish.
**Environment response:** Fuzzy alias matching gives partial credit; exact type names give full reward.
**Why it's hard:** 15 closely related types with overlapping patterns require precise OWASP knowledge.

### Failure Mode 3 — False Positive Spam
**Symptom:** Agent reports SHA-256 usage as `Weak Cryptography`, or Flask `SECRET_KEY` as `Hardcoded Secret`.
**Cause:** Pattern matching without semantic understanding (SHA-256 is safe; Flask SECRET_KEY is standard).
**Environment response:** `-0.1` false positive penalty degrades episode score.
**Why it's hard:** The vulnerable code is designed to look realistic — it includes safe patterns that trigger naive scanners.

### Failure Mode 4 — File Blindness (Task 2)
**Symptom:** Agent scans only initially visible files and marks complete without requesting hidden files.
**Cause:** Agent doesn't model that hidden files exist; no incentive to explore without explicit prompting.
**Environment response:** Static scan hints and suspicious file flags guide agents toward hidden files.
**Why it's hard:** Two of Task 2's 5 vulnerabilities are in hidden files — missing them caps score at 0.60.

### Failure Mode 5 — Duplicate Reporting
**Symptom:** Agent reports the same `(file, vulnerability_type)` pair 2–3 times, wasting steps.
**Cause:** LLM loses track of already-reported findings across a long message history.
**Environment response:** `-0.05` duplicate penalty; agent-side deduplication blocks redundant env calls.
**Why it's hard:** On Task 3 with 40 max steps, duplicate loops can consume 15+ steps before the agent self-corrects.

## Setup Instructions

### Prerequisites
- Python 3.11+
- pip
- Docker (optional)
- uv (recommended for lockfile + validator workflow)

### Fresh Machine Setup (Windows / macOS / Linux)

```bash
# 1) Clone
git clone <YOUR_REPO_URL>
cd "openenv hack"

# 2) Create venv
Windows (PowerShell): python -m venv .venv && .\.venv\Scripts\Activate.ps1
macOS/Linux:         python3 -m venv .venv && source .venv/bin/activate

# 3) Install deps
pip install --upgrade pip
pip install -r requirements.txt

# 4) (Recommended) sync + validate with uv
uv lock
uv run openenv validate

# 5) Run tests
pytest tests/ -v
```

Create `.env` in repo root:

```env
HF_TOKEN=<your_token>
API_BASE_URL=<your_api_base_url>
MODEL_NAME=<your_model_name>
ENV_BASE_URL=http://localhost:7860
```

The inference runner loads these from `.env` using `python-dotenv`.  
For reproducible submissions, treat `.env` values as the source of truth for:
- `API_BASE_URL`
- `MODEL_NAME`
- `ENV_BASE_URL`
- `HF_TOKEN`

### Local Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Start the API server
uvicorn main:app --host 0.0.0.0 --port 7860

# Alternative server entrypoint
python -m server.app
```

### Docker Setup

```bash
# Build the image
docker build -t security-scanner .

# Run the container
docker run -p 7860:7860 security-scanner
```

### HuggingFace Space

Deploy via the standard HF Spaces Docker workflow:
1. Create a new Space with Docker SDK
2. Push this repository to the Space
3. The `Dockerfile` is pre-configured for port 7860

### Running Inference

```bash
# Set your API key
export HF_TOKEN=your-api-key-here

# Optionally configure model and API
export API_BASE_URL=https://integrate.api.nvidia.com/v1
export MODEL_NAME=meta/llama-3.1-70b-instruct

# Start the environment server (in one terminal)
uvicorn main:app --host 0.0.0.0 --port 7860

# Run the agent (in another terminal)
python inference.py
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HF_TOKEN` | Yes (or `OPENAI_API_KEY`) | — | API key for the OpenAI-compatible LLM |
| `OPENAI_API_KEY` | Alternative to `HF_TOKEN` | — | Same role as `HF_TOKEN` if your runner sets this name |
| `API_BASE_URL` | Yes for judged runs | Hugging Face router URL in `inference.py` if unset | Override in `.env` / Space secrets for your provider |
| `MODEL_NAME` | Yes for judged runs | Qwen default in `inference.py` if unset | Override to match your endpoint (e.g. Llama on NIM) |
| `ENV_BASE_URL` | Yes when env is remote | `http://localhost:7860` | OpenEnv FastAPI base URL (Space URL when inference runs off-container) |
| `LOCAL_IMAGE_NAME` / `IMAGE_NAME` | No | — | Only for `from_docker_image` workflows; recorded in `inference_results.json` if set |

## API Reference

### Validate OpenEnv Compliance
```bash
curl http://localhost:7860/validate
```

Expected response:
```json
{
  "openenv_compliant": true,
  "spec_version": "1.0",
  "environment_name": "security-vulnerability-scanner",
  "endpoints": ["/reset", "/step", "/state", "/tasks", "/health", "/validate"],
  "observation_fields": [
    "files", "current_findings", "step_number", "task_id",
    "feedback", "remaining_steps", "active_insights", "suspicious_files"
  ],
  "action_types": ["report_vulnerability", "request_file", "mark_complete", "add_note"],
  "tasks": [
    {"id": 1, "name": "Single File Audit", "difficulty": "easy"},
    {"id": 2, "name": "Multi-File Flask App", "difficulty": "medium"},
    {"id": 3, "name": "Real-World Project Audit", "difficulty": "hard"}
  ]
}
```

### All Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/tasks` | List all tasks with metadata |
| `POST` | `/reset` | Start a new episode (`{"task_id": 1\|2\|3}`) |
| `POST` | `/step` | Submit an action and get result |
| `GET` | `/state` | Get current episode state + security analysis |
| `GET` | `/validate` | OpenEnv spec compliance info |

## Project Structure

```
├── .env                         # Local runtime variables / API key
├── pyproject.toml               # Project metadata and dependency spec
├── uv.lock                      # Locked dependency graph (uv)
├── requirements.txt             # Pip-compatible dependency list
├── openenv.yaml                 # OpenEnv configuration
├── Dockerfile                   # Container deployment
├── main.py                      # FastAPI server entrypoint (port 7860)
├── server/
│   └── app.py                   # Alternative ASGI server entrypoint
├── inference.py                 # LLM + deterministic baseline runner
├── check_hack_submission        # End-to-end submission validation script
├── changes.md                   # Primary change log
├── changes_additional.md        # Additional enhancement notes (incl. triage)
├── environment/
│   ├── config.py                # Feature flags and runtime toggles
│   ├── models.py                # Pydantic models & enums
│   ├── env.py                   # SecurityScannerEnv (reset/step/state)
│   ├── state_manager.py         # Episode state + cached triage/coverage metrics
│   ├── reward.py                # Reward and episode score computation
│   ├── chain_objective.py       # Attack-chain objective helpers
│   ├── data/
│   │   ├── task1/               # 1 file, 3 vulns (easy)
│   │   ├── task2/               # 4 files, 5 vulns (medium)
│   │   └── task3/               # 5 files, 7 vulns (hard)
│   ├── tasks/                   # Task implementations
│   ├── graders/                 # 3 grading strategies
│   └── security_analysis/       # Static/dataflow/chain/exploitability analyzers
└── tests/                       # Unit tests (pytest)
```

## License
This project was built for the OpenEnv Hackathon by Team Suika.
