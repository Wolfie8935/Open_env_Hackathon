# Security Vulnerability Scanner

An AI agent environment for automated security code review and vulnerability detection. Built as an [OpenEnv](https://openenv.dev)-compatible reinforcement learning environment where agents analyze Python codebases to find planted security vulnerabilities across 3 tasks of increasing difficulty.

## Environment Description and Motivation

Security code review is a critical but time-consuming process that requires deep expertise. This environment trains AI agents to perform systematic vulnerability detection on Python codebases, scoring them on accuracy, precision, and fix quality.

**Why this matters:**
- Automated security auditing can catch vulnerabilities before production deployment
- RL-trained agents can learn optimal scanning strategies through trial and error
- The environment rewards both detection accuracy and actionable remediation advice

The environment simulates a realistic security audit scenario where an agent receives source code files, analyzes them for vulnerabilities, and reports findings with exact details. Three tasks cover progressively harder scenarios — from a single-file module to a full SaaS platform API with hidden files.

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

Each `Finding` contains: `file`, `line_number`, `vulnerability_type`, `severity`, `description`, `suggested_fix`.

## Action Space

The agent can take one of 4 discrete actions per step:

| Action | Parameters | Description |
|--------|-----------|-------------|
| `report_vulnerability` | `file`, `line_number`, `vulnerability_type`, `severity`, `description`, `suggested_fix` | Report a found vulnerability with type, exact line, severity, and fix |
| `request_file` | `filename` | Request to see a hidden file not initially visible |
| `mark_complete` | *(none)* | Signal that the security scan is complete |
| `add_note` | `note` | Add a reasoning note (contributes to scoring in Task 3) |

## Task Descriptions

| Task | Name | Difficulty | Files | Vulnerabilities | Max Steps | Target Score |
|------|------|-----------|-------|-----------------|-----------|-------------|
| 1 | Single File Audit | Easy | 1 | 3 | 10 | 0.90+ |
| 2 | Multi-File Flask App | Medium | 4 (2 hidden) | 5 | 20 | 0.80+ |
| 3 | Real-World Project Audit | Hard | 5 (3 hidden) | 7 | 40 | 0.50+ |

### Task 1 — Single File Audit (Easy)
Analyze a single Python module (user management backend) with a database manager and data processor. All 3 vulnerabilities are in one file that is fully visible from the start.

### Task 2 — Multi-File Flask App (Medium)
Audit a Flask-based file manager application with user accounts and an admin panel. The app has 4 source files — only 2 are initially visible. The agent must use `request_file` to reveal hidden files.

### Task 3 — Real-World Project Audit (Hard)
Audit a production-style SaaS platform REST API with authentication, webhooks, XML parsing, and user management. 5 source files, 3 hidden. Severity accuracy scoring is enabled, and reasoning notes contribute bonus points.

## Reward Function

| Signal | Condition | Value |
|--------|-----------|-------|
| Type match | Vulnerability type matches ground truth (fuzzy) | +0.3 |
| Line bonus | Line number within ±2 of ground truth | +0.1 |
| Fix quality | Suggested fix contains security-relevant keywords | +0.1 |
| Severity match | Severity matches ground truth (Task 3 only) | +0.1 |
| False positive | Reported vulnerability not in ground truth | -0.1 |
| Duplicate | Same vulnerability reported twice | 0.0 |
| Notes bonus | Security reasoning notes submitted (Task 3 only) | +0.05 (episode) |

**Episode score formula:**
```
max_per_finding = 0.5 (Tasks 1-2) or 0.6 (Task 3)
max_possible = num_vulnerabilities × max_per_finding
raw_score = sum(max(0, step_reward) for each finding)
final_score = clamp(raw_score / max_possible, 0.0, 1.0)
```

## Vulnerability Types

The environment recognizes 15 vulnerability types:

1. SQL Injection
2. Hardcoded Secret
3. Command Injection
4. Path Traversal
5. Insecure Deserialization
6. Broken Authentication
7. Weak Cryptography
8. SSRF
9. XXE Injection
10. IDOR
11. Mass Assignment
12. Timing Attack
13. CORS Misconfiguration
14. Debug Mode
15. JWT Misconfiguration

## Setup Instructions

### Prerequisites
- Python 3.11+
- pip
- Docker (optional)

### Local Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Start the API server
uvicorn main:app --host 0.0.0.0 --port 7860
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
| `HF_TOKEN` | Yes | — | API key for the LLM provider |
| `API_BASE_URL` | No | `https://integrate.api.nvidia.com/v1` | Base URL for the LLM API |
| `MODEL_NAME` | No | `meta/llama-3.1-70b-instruct` | Model identifier |

## Baseline Scores

Results using Llama 3.1 70B Instruct via NVIDIA NIM:

| Task | Score | Findings | False Positives | Steps Used |
|------|-------|----------|-----------------|------------|
| Task 1 (Easy) | 0.933 | 3/3 | 0 | 5 |
| Task 2 (Medium) | 0.680 | 4/5 | 0 | 12 |
| Task 3 (Hard) | 0.214 | 2/7 | 2 | 8 |
| **Overall** | **0.609** | — | — | — |

## Example Agent Interaction

```bash
# 1. Reset to Task 1
curl -X POST http://localhost:7860/reset \
  -H "Content-Type: application/json" \
  -d '{"task_id": 1}'
# → Returns Observation with visible files and remaining_steps=10

# 2. Report a vulnerability
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "report_vulnerability",
    "payload": {
      "file": "vulnerable_code.py",
      "line_number": 9,
      "vulnerability_type": "Hardcoded Secret",
      "severity": "High",
      "description": "API key is hardcoded as a string literal at module level, exposing credentials in source code",
      "suggested_fix": "Use os.environ.get() to read the API key from environment variables instead of hardcoding it"
    }
  }'
# → Returns StepResult with reward: +0.50, done: false

# 3. Report another vulnerability
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{
    "action_type": "report_vulnerability",
    "payload": {
      "file": "vulnerable_code.py",
      "line_number": 25,
      "vulnerability_type": "SQL Injection",
      "severity": "Critical",
      "description": "User input is directly interpolated into SQL query using f-string without parameterization",
      "suggested_fix": "Use parameterized queries with cursor.execute(query, (param,)) to prevent SQL injection attacks"
    }
  }'
# → Returns StepResult with reward: +0.50, done: false

# 4. Mark complete
curl -X POST http://localhost:7860/step \
  -H "Content-Type: application/json" \
  -d '{"action_type": "mark_complete", "payload": {}}'
# → Returns StepResult with done: true, info.episode_score: 0.667
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/tasks` | List all tasks with metadata |
| `POST` | `/reset` | Start a new episode (`{"task_id": 1\|2\|3}`) |
| `POST` | `/step` | Submit an action and get result |
| `GET` | `/state` | Get current episode state |
| `GET` | `/validate` | OpenEnv spec compliance info |

## Project Structure

```
├── .env                    # API key (HF_TOKEN)
├── requirements.txt        # Dependencies (pinned)
├── openenv.yaml            # OpenEnv configuration
├── Dockerfile              # Container deployment
├── main.py                 # FastAPI server (port 7860)
├── inference.py            # AI agent loop
├── environment/
│   ├── models.py           # Pydantic models & enums
│   ├── env.py              # SecurityScannerEnv (reset/step/state)
│   ├── state_manager.py    # Mutable episode state
│   ├── reward.py           # Pure reward computation
│   ├── data/
│   │   ├── task1/          # 1 file, 3 vulns (easy)
│   │   ├── task2/          # 4 files, 5 vulns (medium)
│   │   └── task3/          # 5 files, 7 vulns (hard)
│   ├── tasks/              # Task implementations
│   └── graders/            # 3 grading strategies
└── tests/                  # Unit tests (pytest)
```

## License

This project was built for the OpenEnv Hackathon by Team Suika.
