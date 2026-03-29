"""
Inference Script — Security Vulnerability Scanner Agent
Drives an LLM agent through all 3 tasks using a configurable API endpoint.
Each task: reset → observe → [call LLM → parse JSON → step] → until done.

Usage:
    python inference.py

Environment variables:
    HF_TOKEN        — required, your API key
    API_BASE_URL    — optional, defaults to https://integrate.api.nvidia.com/v1
    MODEL_NAME      — optional, defaults to meta/llama-3.1-70b-instruct
    ENV_BASE_URL    — optional, defaults to http://localhost:7860
"""

import json
import os
import re
import time
from typing import Optional

import httpx
from openai import OpenAI
from dotenv import load_dotenv

load_dotenv()

# ─── Configuration ────────────────────────────────────────────

API_KEY = os.environ.get("HF_TOKEN")
API_BASE_URL = os.environ.get("API_BASE_URL")
MODEL_NAME = os.environ.get("MODEL_NAME")
ENV_BASE_URL = os.environ.get("ENV_BASE_URL")

if not API_KEY:
    raise EnvironmentError(
        "HF_TOKEN environment variable is required. "
        "Set it in your .env file or export it."
    )

API_BASE_URL = os.environ.get(
    "API_BASE_URL", API_BASE_URL
)
MODEL_NAME = os.environ.get(
    "MODEL_NAME", MODEL_NAME
)
ENV_BASE_URL = os.environ.get("ENV_BASE_URL", ENV_BASE_URL)

client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)
http_client = httpx.Client(base_url=ENV_BASE_URL, timeout=30.0)

# ─── System Prompt ────────────────────────────────────────────

SYSTEM_PROMPT = """You are an expert application security engineer with 10 years of experience conducting code audits for Fortune 500 companies. You are methodical, precise, and thorough.

## YOUR TASK
You will be given Python source code files. Your job is to identify security vulnerabilities, report them with exact details, and suggest concrete fixes. You are scored on accuracy — false positives hurt your score.

## VULNERABILITY TYPES — USE THESE EXACT NAMES (case sensitive as shown)
You must use ONLY these exact vulnerability type strings when reporting:

1.  "SQL Injection"              — f-string or %s in SQL queries, no parameterization
2.  "Hardcoded Secret"           — API keys, passwords, tokens as string literals in code (NOT JWT secrets — see #15)
3.  "Command Injection"          — eval(), exec(), os.system() on user input
4.  "Path Traversal"             — os.path.join with user input, open() without path sanitization
5.  "Insecure Deserialization"   — pickle.loads(), yaml.load() without Loader on user data
6.  "Broken Authentication"      — endpoints with no auth check, missing login_required
7.  "Weak Cryptography"          — MD5 or SHA1 for PASSWORD hashing (not for request IDs)
8.  "SSRF"                       — requests.get(user_controlled_url) with no URL validation
9.  "XXE Injection"              — xml.etree.ElementTree or ET.parse on user input without defusedxml
10. "IDOR"                       — fetching DB record by request param ID without checking ownership
11. "Mass Assignment"            — passing request.data or full dict to model constructor or __dict__.update()
12. "Timing Attack"              — comparing tokens/passwords with == instead of hmac.compare_digest()
13. "CORS Misconfiguration"      — CORS origins set to * especially with credentials=True
14. "Debug Mode"                  — DEBUG = True in production config
15. "JWT Misconfiguration"       — JWT_SECRET or jwt_secret as a hardcoded string literal

## SEVERITY LEVELS
- Critical: Direct exploitability, leads to RCE, data breach, or full auth bypass
- High: Significant risk, exploitable with moderate effort
- Medium: Risk exists but requires specific conditions
- Low: Best practice violation, limited direct exploitability

## STRATEGY — FOLLOW THIS EXACTLY
1. First, read ALL currently visible files completely top to bottom
2. Request ALL hidden files immediately using request_file — do this before reporting anything
3. After seeing all files, analyze methodically:
   - Check every function that handles user input
   - Check every database query
   - Check every file operation
   - Check every authentication decorator (or lack of one)
   - Check every import — pickle, xml, yaml, eval are red flags
   - Check config files for hardcoded secrets and debug flags
   - Check CORS configuration
4. Report vulnerabilities from Critical to Low severity
5. For each finding, write a suggested_fix of at least 30 words that names the specific safe alternative
6. Call mark_complete only when you have reviewed every single file

## SPECIFIC PATTERNS TO FIND
- `eval(` anywhere near user input → Command Injection
- `f"SELECT` or `"SELECT...{` → SQL Injection
- `pickle.loads(` → Insecure Deserialization
- `ET.parse(` or `ElementTree.parse(` or `ET.fromstring(` on request data → XXE Injection
- `requests.get(url)` where url comes from request → SSRF
- `== token` or `== stored` for auth comparison (using == instead of hmac.compare_digest) → Timing Attack
- `JWT_SECRET = "` any hardcoded jwt secret → JWT Misconfiguration
- `DEBUG = True` → Debug Mode in Production
- `request.data` or `request.json()` passed to model constructor or `__dict__.update()` → Mass Assignment
- `filter_by(id=request_param)` or `.get(id)` without user ownership check → IDOR
- `os.path.join(base, user_input)` with open() → Path Traversal
- `hashlib.md5(password` or `hashlib.sha1(password` → Weak Cryptography
- `CORS(app, origins="*"` → CORS Misconfiguration
- route with no @login_required or auth check → Broken Authentication
- API keys, passwords, or tokens as hardcoded string literals → Hardcoded Secret

## CRITICAL REMINDERS
- "Timing Attack" is NOT "Weak Cryptography" — if you see == comparison for tokens/passwords, use "Timing Attack"
- "JWT Misconfiguration" is NOT "Hardcoded Secret" — if you see a hardcoded JWT secret key, use "JWT Misconfiguration"
- Never call mark_complete until you have checked EVERY file for path traversal, open(), file read operations specifically
- Look for any endpoint that fetches a record using an ID from the request without checking ownership → "IDOR"
- Look for any place where request.data, request.json(), or user-supplied dict is passed directly to a model constructor or __dict__.update() → "Mass Assignment"
- Look for xml.etree.ElementTree.parse() or ET.fromstring() called on user-supplied data without defusedxml → "XXE Injection"

## OUTPUT FORMAT
You MUST respond with ONLY a valid JSON object. No text before or after. No markdown. No explanation outside the JSON.

Examples:
{"action_type": "request_file", "payload": {"filename": "utils.py"}}
{"action_type": "report_vulnerability", "payload": {"file": "app.py", "line_number": 35, "vulnerability_type": "Path Traversal", "severity": "High", "description": "The download_file function joins user-supplied filename with base directory without sanitization, allowing directory traversal to access files outside the intended directory.", "suggested_fix": "Use os.path.basename() to strip directory components from user input, then validate the resolved path starts with the expected base directory using os.path.realpath()."}}
{"action_type": "add_note", "payload": {"note": "Reviewing auth.py for timing vulnerabilities in token comparison"}}
{"action_type": "mark_complete", "payload": {}}

Never use a vulnerability type not in the list above. Never call mark_complete before reviewing all files.
"""


# ─── Helper Functions ─────────────────────────────────────────

def env_reset(task_id: int) -> dict:
    """Reset the environment to start a new task episode."""
    response = http_client.post("/reset", json={"task_id": task_id})
    response.raise_for_status()
    return response.json()


def env_step(action: dict) -> dict:
    """Send an action to the environment and get the result."""
    response = http_client.post("/step", json=action)
    response.raise_for_status()
    return response.json()


def format_observation(obs: dict) -> str:
    """Format an observation into a readable prompt for the LLM."""
    parts = []

    parts.append(f"## Task {obs['task_id']} — Step {obs['step_number']}")
    parts.append(f"Remaining steps: {obs['remaining_steps']}")
    parts.append(f"Feedback: {obs['feedback']}")
    parts.append("")

    # Show source files
    parts.append("## Source Files")
    for filename, content in sorted(obs.get("files", {}).items()):
        parts.append(f"\n### File: {filename}")
        lines = content.split("\n")
        numbered = "\n".join(f"{i+1}: {line}" for i, line in enumerate(lines))
        parts.append(f"```python\n{numbered}\n```")

    # Show current findings
    if obs.get("current_findings"):
        parts.append("\n## Already Reported Findings")
        for f in obs["current_findings"]:
            parts.append(
                f"- [{f['severity']}] {f['vulnerability_type']} in {f['file']} "
                f"at line {f['line_number']}"
            )

    parts.append(
        "\n## Your Turn\n"
        "Analyze the code and respond with a single JSON action. "
        "If you haven't seen all files yet, request them first. "
        "Then report vulnerabilities. When done, mark_complete."
    )

    return "\n".join(parts)


def extract_json_action(raw_text: str) -> Optional[dict]:
    """Extract a JSON action from LLM response even if surrounded by prose.

    Tries multiple strategies:
    1. Direct JSON parse
    2. Extract from markdown code fences
    3. Find deepest nested JSON object
    4. Fallback: add_note with raw text
    """
    raw_text = raw_text.strip()

    # Strategy 1: Direct parse
    try:
        return json.loads(raw_text)
    except json.JSONDecodeError:
        pass

    # Strategy 2: Extract from code fences
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw_text, re.DOTALL)
    if fence_match:
        try:
            return json.loads(fence_match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Strategy 3: Find JSON objects (supports one level of nesting)
    matches = re.findall(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)?\}', raw_text, re.DOTALL)
    for match in matches:
        try:
            parsed = json.loads(match)
            if "action_type" in parsed:
                return parsed
        except json.JSONDecodeError:
            continue

    # Strategy 4: Try finding first { ... } block greedily
    brace_match = re.search(r"\{.*\}", raw_text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group())
        except json.JSONDecodeError:
            pass

    # Fallback: add_note so episode doesn't crash
    return {"action_type": "add_note", "payload": {"note": f"Could not parse response: {raw_text[:200]}"}}


def call_llm_with_retry(messages: list[dict], max_retries: int = 3) -> str:
    """Call the LLM API with exponential backoff retry."""
    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=messages,
                temperature=0.1,
                max_tokens=500,
            )
            return response.choices[0].message.content
        except Exception as e:
            if attempt == max_retries - 1:
                raise RuntimeError(f"LLM API failed after {max_retries} attempts: {e}")
            wait_time = 5 * (2 ** attempt)
            print(f"  ⚠ LLM API error (attempt {attempt + 1}): {e}. Retrying in {wait_time}s...", flush=True)
            time.sleep(wait_time)
    return ""

# ─── Main Agent Loop ──────────────────────────────────────────

def run_task(task_id: int) -> dict:
    """Run the agent through a single task episode.

    Returns a summary dict with final score and step logs.
    """
    obs = env_reset(task_id)
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    step_logs = []
    done = False
    max_fallback_steps = obs.get("remaining_steps", 40) + 2
    false_positives = 0
    true_positives = 0
    gt_count = 0

    print(f"\n{'='*60}", flush=True)
    print(f"TASK {task_id}: {obs.get('feedback', 'Started')[:80]}", flush=True)
    print(f"{'='*60}", flush=True)

    step_count = 0
    while not done and step_count < max_fallback_steps:
        step_count += 1

        # Build user message from observation
        user_msg = format_observation(obs)
        messages.append({"role": "user", "content": user_msg})

        # Call LLM
        raw_response = call_llm_with_retry(messages)
        messages.append({"role": "assistant", "content": raw_response})

        # Parse JSON action
        action = extract_json_action(raw_response)
        if action is None:
            # Fallback: ask LLM to fix its output
            messages.append({
                "role": "user",
                "content": "Your response was not valid JSON. Please respond with ONLY a valid JSON object matching one of the action formats."
            })
            raw_response = call_llm_with_retry(messages)
            messages.append({"role": "assistant", "content": raw_response})
            action = extract_json_action(raw_response)

            if action is None:
                print(f"  Step {step_count} | ⚠ Could not parse action, using mark_complete", flush=True)
                action = {"action_type": "mark_complete", "payload": {}}

        # Send to environment
        result = env_step(action)

        reward = result.get("reward", 0)
        feedback = result.get("observation", {}).get("feedback", "")
        action_type = action.get("action_type", "unknown")

        # Track true/false positives
        if action_type == "report_vulnerability":
            if reward > 0:
                true_positives += 1
            elif reward < 0:
                false_positives += 1

        step_logs.append({
            "step": step_count,
            "action_type": action_type,
            "action": action,
            "reward": reward,
            "feedback": feedback,
        })

        reward_str = f"{reward:+.2f}" if reward != 0 else " 0.00"
        print(f"  Step {step_count:2d} | {action_type:<25s} | reward: {reward_str} | {feedback[:60]}", flush=True)

        obs = result.get("observation", obs)
        done = result.get("done", False)

        # Update ground truth count from info
        gt_count = result.get("info", {}).get("ground_truth_count", gt_count)

        # Keep message history manageable
        if len(messages) > 30:
            messages = messages[:1] + messages[-20:]

    final_score = result.get("info", {}).get("episode_score", 0.0)

    print(f"\n  ── Task {task_id} Summary ──", flush=True)
    print(f"  Vulnerabilities found: {true_positives} / {gt_count}", flush=True)
    print(f"  False positives: {false_positives}", flush=True)
    print(f"  Steps used: {step_count} / {max_fallback_steps - 2}", flush=True)
    print(f"  Score: {final_score:.3f}", flush=True)

    # ── Collect security analysis summary from environment (if available) ──
    security_analysis = {}
    try:
        analysis_resp = http_client.get("/state")
        analysis_resp.raise_for_status()
        state = analysis_resp.json()

        # REAL analysis summary from environment
        security_analysis = state.get("security_analysis", {})

    except Exception:
        security_analysis = {"status": "analysis_summary_unavailable"}

    # Detect missed vulnerabilities
    missed_vulnerabilities = []

    try:
        state_resp = http_client.get("/state")
        state_resp.raise_for_status()
        state = state_resp.json()

        ground_truth = state.get("ground_truth", [])
        findings = state.get("findings", [])

        reported = {
        (f["file"], f["line_number"], f["vulnerability_type"])
        for f in findings
        }

        for gt in ground_truth:
            key = (gt["file"], gt["line"], gt["type"])
            if key not in reported:
                missed_vulnerabilities.append(gt)

    except Exception:
        missed_vulnerabilities = []

    return {
    "task_id": task_id,
    "final_score": final_score,
    "steps": step_logs,
    "total_steps": step_count,
    "true_positives": true_positives,
    "false_positives": false_positives,
    "ground_truth_count": gt_count,
    "missed_vulnerabilities": missed_vulnerabilities,
    "security_analysis": security_analysis
    }

def main():
    """Run the agent through all 3 tasks and print summary."""
    start_time = time.time()

    print("\n" + "=" * 60, flush=True)
    print("  SECURITY VULNERABILITY SCANNER — INFERENCE", flush=True)
    print(f"  Model: {MODEL_NAME}", flush=True)
    print(f"  API: {API_BASE_URL}", flush=True)
    print(f"  Environment: {ENV_BASE_URL}", flush=True)
    print("=" * 60, flush=True)

    # Verify environment is running
    try:
        health = http_client.get("/health")
        health.raise_for_status()
        print(f"  Environment health: {health.json()}", flush=True)
    except Exception as e:
        print(f"\n  ✖ Cannot reach environment at {ENV_BASE_URL}: {e}", flush=True)
        print("  Make sure the server is running: uvicorn main:app --port 7860", flush=True)
        return

    results = []
    for task_id in [1, 2, 3]:
        result = run_task(task_id)
        results.append(result)

    elapsed = time.time() - start_time
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)

    # Print final summary (once)
    print("\n" + "=" * 60, flush=True)
    print("  FINAL SUMMARY", flush=True)
    print("=" * 60, flush=True)

    task_names = {1: "Easy", 2: "Medium", 3: "Hard"}
    total_score = 0
    for r in results:
        tid = r["task_id"]
        score = r["final_score"]
        total_score += score
        tp = r["true_positives"]
        gt = r["ground_truth_count"]
        fp = r["false_positives"]
        print(
            f"  Task {tid} ({task_names[tid]:>6s}):  {score:.3f}  "
            f"({tp}/{gt} found, {fp} FP, {r['total_steps']} steps)",
            flush=True,
        )

    overall = total_score / len(results) if results else 0
    print(f"\n  Overall:         {overall:.3f}", flush=True)
    print(f"  Time elapsed:    {minutes}m {seconds}s", flush=True)
    print("=" * 60, flush=True)

    # Save results to file
    results_file = "inference_results.json"
    with open(results_file, "w") as f:
        json.dump({
            "results": results,
            "overall_score": overall,
            "elapsed_seconds": elapsed,
            "model": MODEL_NAME,
        }, f, indent=2)
    print(f"\n  Results saved to {results_file}", flush=True)


if __name__ == "__main__":
    main()
