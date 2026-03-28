# Security Vulnerability Scanner — Run Guide

Step-by-step instructions to set up, test, and run the full system.

---

## Prerequisites

- **Python 3.11+** installed and on PATH
- **pip** available
- **Docker** (optional, for containerized deployment)
- **HF_TOKEN** (already in your `.env` file)

---

## Step 1 — Install Dependencies

Open a terminal in the project folder (`c:\Users\amanc\Desktop\openenv hack`) and run:

```bash
pip install -r requirements.txt
```

This installs: FastAPI, Uvicorn, Pydantic, OpenAI client, httpx, pytest, python-dotenv.

---

## Step 2 — Verify Ground Truth Data

Confirm all vulnerable code files have correct ground truth entries:

```bash
# Task 1: should print 3 entries
python -c "from environment.data.task1.vulnerable_code import GROUND_TRUTH; print(f'Task 1: {len(GROUND_TRUTH)} vulnerabilities'); [print(f'  - Line {g[\"line\"]}: {g[\"type\"]} ({g[\"severity\"]})') for g in GROUND_TRUTH]"

# Task 2: should print 5 entries
python -c "from environment.data.task2 import TASK2_GROUND_TRUTH; print(f'Task 2: {len(TASK2_GROUND_TRUTH)} vulnerabilities'); [print(f'  - {g[\"file\"]} line {g[\"line\"]}: {g[\"type\"]} ({g[\"severity\"]})') for g in TASK2_GROUND_TRUTH]"

# Task 3: should print 7 entries
python -c "from environment.data.task3 import TASK3_GROUND_TRUTH; print(f'Task 3: {len(TASK3_GROUND_TRUTH)} vulnerabilities'); [print(f'  - {g[\"file\"]} line {g[\"line\"]}: {g[\"type\"]} ({g[\"severity\"]})') for g in TASK3_GROUND_TRUTH]"
```

---

## Step 3 — Verify Ground Truth is Hidden from Agent

```bash
python -c "from environment.tasks.task1_single_file import Task1SingleFile; t = Task1SingleFile(); content = list(t.get_initial_files().values())[0]; assert 'GROUND_TRUTH' not in content; print('OK: Ground truth is correctly hidden from agent')"
```

---

## Step 4 — Run Tests

```bash
pytest tests/ -v
```

**Expected output:** All tests pass (~25 tests across 3 files).

If any tests fail, check the error message — most common issues:
- Import errors → Step 1 didn't complete
- Line number mismatches → Verify with `Step 2` commands

---

## Step 5 — Start the API Server

```bash
uvicorn main:app --host 0.0.0.0 --port 7860
```

The server starts on `http://localhost:7860`. You should see:
```
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://0.0.0.0:7860
```

Leave this terminal running and open a **new terminal** for the next steps.

---

## Step 6 — Test API with curl (in new terminal)

Run these in order:

### 6.1 Health check
```bash
curl http://localhost:7860/health
```
Expected: `{"status":"ok","version":"1.0.0"}`

### 6.2 List tasks
```bash
curl http://localhost:7860/tasks
```
Expected: JSON with 3 tasks (easy/medium/hard)

### 6.3 Reset to Task 1
```bash
curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" -d "{\"task_id\": 1}"
```
Expected: Observation JSON with `vulnerable_code.py` content and `remaining_steps: 10`

### 6.4 Submit a finding
```bash
curl -X POST http://localhost:7860/step -H "Content-Type: application/json" -d "{\"action_type\": \"report_vulnerability\", \"payload\": {\"file\": \"vulnerable_code.py\", \"line_number\": 9, \"vulnerability_type\": \"Hardcoded Secret\", \"severity\": \"High\", \"description\": \"API key is hardcoded in source code at module level\", \"suggested_fix\": \"Use os.environ.get() to read API key from environment variables\"}}"
```
Expected: `reward` around `+0.50` (type match + line match + fix quality)

### 6.5 Get state
```bash
curl http://localhost:7860/state
```
Expected: JSON with `findings` containing 1 entry, `step_number: 1`

### 6.6 Mark complete
```bash
curl -X POST http://localhost:7860/step -H "Content-Type: application/json" -d "{\"action_type\": \"mark_complete\", \"payload\": {}}"
```
Expected: `done: true`, `episode_score` in info dict

---

## Step 7 — Run the AI Agent (Inference)

Make sure:
1. The API server is running (Step 5)
2. Your `.env` file has `HF_TOKEN=nvapi-...` (already set)

Then in a **new terminal**:

```bash
python inference.py
```

**What happens:**
- The agent connects to your local API server
- Runs through all 3 tasks (easy → medium → hard)
- Calls NVIDIA NIM (Llama 3.1 70B) for each step
- Prints per-step actions, rewards, and feedback
- Saves results to `inference_results.json`

**Expected runtime:** 5–15 minutes depending on NIM API latency.

**Expected output:**
```
============================================================
  SECURITY VULNERABILITY SCANNER — INFERENCE
  Model: meta/llama-3.1-70b-instruct
  Environment: http://localhost:7860
============================================================
  Environment health: {'status': 'ok', 'version': '1.0.0'}

============================================================
TASK 1: Episode started for Task 1: Single File Audit...
============================================================
  Step  1 | request_file              | reward:  0.00 | ...
  Step  2 | report_vulnerability      | reward: +0.50 | ...
  ...

  TASK 1 FINAL SCORE: 0.833

============================================================
FINAL SUMMARY
============================================================
  Task 1 (  Easy):  0.833  (5 steps)
  Task 2 (Medium):  0.640  (12 steps)
  Task 3 (  Hard):  0.471  (18 steps)

  Overall:         0.648
  Time elapsed:    8m 22s
============================================================
```

---

## Step 8 — Docker Build & Run (Optional)

```bash
# Build the image
docker build -t security-scanner .

# Run the container
docker run -p 7860:7860 security-scanner

# Then run inference pointing to the container
python inference.py
```

---

## Project Structure Summary

```
openenv hack/
├── .env                    ← Your API key (HF_TOKEN)
├── requirements.txt        ← Dependencies (lean, pinned)
├── openenv.yaml            ← OpenEnv configuration
├── Dockerfile              ← Container deployment
├── main.py                 ← FastAPI server (port 7860)
├── inference.py            ← AI agent loop (NVIDIA NIM)
├── environment/
│   ├── models.py           ← All Pydantic models & enums
│   ├── env.py              ← SecurityScannerEnv (reset/step/state)
│   ├── state_manager.py    ← Mutable episode state
│   ├── reward.py           ← Pure reward computation
│   ├── data/
│   │   ├── task1/          ← 1 file, 3 vulns (easy)
│   │   ├── task2/          ← 4 files, 5 vulns (medium)
│   │   └── task3/          ← 5 files, 7 vulns (hard)
│   ├── tasks/              ← Task implementations
│   └── graders/            ← 3 grading strategies
└── tests/                  ← Unit tests (pytest)
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `ModuleNotFoundError` | Run `pip install -r requirements.txt` |
| `ConnectionRefused` on inference | Make sure `uvicorn main:app --port 7860` is running |
| NIM API errors | Check `HF_TOKEN` in `.env` is valid |
| Low scores | Expected — agent performance varies with model |
| `openenv validate` fails | Check `openenv.yaml` format matches your CLI version |

---

## Key Commands Cheatsheet

```bash
# Install deps
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Start server
uvicorn main:app --host 0.0.0.0 --port 7860

# Run agent
python inference.py

# Docker
docker build -t security-scanner .
docker run -p 7860:7860 security-scanner
```
