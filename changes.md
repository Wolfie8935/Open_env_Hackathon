# OpenEnv Security Scanner — Setup and Migration Guide

This file is a clean setup runbook for getting this repository running on a new system.  
It intentionally avoids command outputs/log dumps and focuses only on process + commands.

---

## 1) Clone the repository

```bash
git clone <YOUR_REPO_URL>
cd "openenv hack"
```

---

## 2) Create and activate a virtual environment

### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### macOS / Linux (bash/zsh)
```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

## 3) Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Optional (if using uv workflow):

```bash
pip install uv
uv sync
```

---

## 4) Configure environment variables

Create a `.env` file at repo root:

```env
HF_TOKEN=<your_hf_or_router_token>
API_BASE_URL=<your_api_base_url>
MODEL_NAME=<your_model_name>
ENV_BASE_URL=http://localhost:7860
```

Minimum required for inference:
- `HF_TOKEN`
- `API_BASE_URL`
- `MODEL_NAME`

---

## 5) Validate project packaging + OpenEnv readiness

```bash
uv lock
uv run openenv validate
```

Expected status: validator reports readiness for multi-mode deployment.

---

## 6) Run unit tests

```bash
pytest tests/ -v
```

---

## 7) Start the environment server

### Option A (direct)
```bash
uvicorn main:app --host 0.0.0.0 --port 7860
```

### Option B (script entry point)
```bash
python -m server.app
```

---

## 8) Run inference (new terminal)

```bash
python inference.py
```

This runs deterministic baseline + LLM run (if token/config is available).

---

## 9) Docker setup (for HF Spaces style deployment)

```bash
docker build -t security-scanner .
docker run -p 7860:7860 security-scanner
```

Then run local API checks or inference against `http://localhost:7860`.

---

## 10) Quick health checks

```bash
curl http://localhost:7860/health
curl http://localhost:7860/tasks
curl -X POST http://localhost:7860/reset -H "Content-Type: application/json" -d "{\"task_id\":1}"
```

---

## 11) Common issues on a fresh machine

- `openenv` command missing:
  - Use `uv run openenv validate` after `uv sync`, or install `openenv-core` in active venv.
- Docker build fails with engine pipe/daemon errors:
  - Start Docker Desktop / Docker daemon first.
- Inference cannot call LLM:
  - Check `.env` values for `HF_TOKEN`, `API_BASE_URL`, `MODEL_NAME`.
- Port conflict on `7860`:
  - Free the port or run server on another port and update `ENV_BASE_URL`.

