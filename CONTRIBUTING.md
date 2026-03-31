# Contributing to Security Vulnerability Scanner

## Project Structure
```
security-scanner-env/
├── environment/
│   ├── data/          ← Vulnerable code files (task1/, task2/, task3/)
│   ├── tasks/         ← Task definitions and file loading
│   ├── graders/       ← Scoring logic per task
│   ├── env.py         ← Core OpenEnv class
│   ├── models.py      ← All Pydantic v2 models
│   ├── reward.py      ← Reward computation
│   └── state_manager.py ← Episode state
├── tests/             ← pytest test suite
├── inference.py       ← Agent runner
└── main.py            ← FastAPI server
```

## Adding a New Task

1. Create `environment/data/taskN/` with your vulnerable Python files
2. Add `GROUND_TRUTH` list at bottom of each file (separated by `# --- GROUND TRUTH ---`)
3. Create `environment/tasks/taskN.py` inheriting from `BaseTask`
4. Create `environment/graders/graderN.py` inheriting from `BaseGrader`
5. Register in `env.py` task loader and `main.py` /tasks endpoint
6. Add tests in `tests/test_graders.py`

## How Graders Work

Each grader receives:
- `findings: list[Finding]` — what the agent reported
- `ground_truth: list[dict]` — the planted vulnerabilities
- Returns `float` in `[0.0, 1.0]`

Grader 1 (Task 1): Exact type match + ±1 line tolerance
Grader 2 (Task 2): Rubric-based, 0.6 type + 0.2 line + 0.2 fix
Grader 3 (Task 3): 0.4 detection + 0.2 severity + 0.2 fix quality + 0.2 reasoning

## Running Tests
```bash
pytest tests/ -v              # all 78 tests
pytest tests/test_graders.py  # graders only
pytest tests/test_env.py      # environment only
```

## Ground Truth Format
```python
GROUND_TRUTH = [
    {
        "line": 25,
        "type": "SQL Injection",      # must match VulnerabilityType enum exactly
        "severity": "Critical",        # Critical / High / Medium / Low
        "file": "app.py",             # filename only, no path
        "fix": "Use parameterized queries"
    },
]
```

## Vulnerability Types (exact strings)
SQL Injection, Hardcoded Secret, Command Injection, Path Traversal,
Insecure Deserialization, Broken Authentication, Weak Cryptography,
SSRF, XXE Injection, IDOR, Mass Assignment, Timing Attack,
CORS Misconfiguration, Debug Mode in Production, JWT Misconfiguration
