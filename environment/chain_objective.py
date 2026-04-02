"""
Chain Objective Layer
Defines explicit exploit-chain missions for each task.
Agents are rewarded for finding chain steps IN ORDER, fast, and without distractions.

Scoring signals:
    +0.15  complete chain found (all steps reported)
    +0.08  ordered discovery (steps reported in logical attack order)
    +0.05  fast start (first chain step found within 5 env steps)
    -0.05  per distraction (non-chain vuln reported before chain complete, max 3)

These bonuses are additive to existing per-step rewards and chain bonuses.
They are applied live during _handle_report() so the agent receives signal
during the episode, not just at mark_complete.
"""

from environment.reward import _types_match

#Chain Objective Definitions
#Each task has exactly one primary chain objective.
#"steps" define the required findings in logical attack order.
#order=1 must be found before order=2 for the ordered bonus.
CHAIN_OBJECTIVES: dict[int, dict] = {
    2: {
        "name": "Full RCE Chain",
        "description": (
            "Find the 2-step path from file download to remote code execution. "
            "Path traversal lets an attacker write files anywhere; "
            "insecure deserialization lets them execute arbitrary code."
        ),
        "display": "Path Traversal (app.py) → Insecure Deserialization (utils.py)",
        "steps": [
            {"file": "app.py",   "type": "Path Traversal",          "order": 1},
            {"file": "utils.py", "type": "Insecure Deserialization", "order": 2},
        ],
        "bonus_complete":     0.15,
        "bonus_ordered":      0.08,
        "bonus_fast_start":   0.05,   # first step within 5 env steps
        "penalty_distraction": -0.05, # per non-chain report before chain complete (max 3)
        "max_distraction_penalty": -0.15,
    },
    3: {
        "name": "Complete Account Takeover",
        "description": (
            "Find the 3-step path to forge tokens and access any account. "
            "Hardcoded JWT secret enables token forgery; timing attack helps "
            "enumerate valid tokens; IDOR exposes any user's data without auth."
        ),
        "display": "JWT Misconfiguration (config.py) → Timing Attack (auth.py) → IDOR (views.py)",
        "steps": [
            {"file": "config.py", "type": "JWT Misconfiguration", "order": 1},
            {"file": "auth.py",   "type": "Timing Attack",         "order": 2},
            {"file": "views.py",  "type": "IDOR",                  "order": 3},
        ],
        "bonus_complete":     0.15,
        "bonus_ordered":      0.08,
        "bonus_fast_start":   0.05,
        "penalty_distraction": -0.05,
        "max_distraction_penalty": -0.15,
    },
    # Task 1 has no chain objective — single file, linear difficulty
    1: None,
}

def get_chain_objective(task_id: int) -> dict | None:
    """Return the chain objective for a task, or None if task has no chain."""
    return CHAIN_OBJECTIVES.get(task_id)

def format_chain_objective_feedback(objective: dict) -> str:
    """Format chain objective as a clear agent-facing message for reset() feedback."""
    if objective is None:
        return ""
    return (
        f"\n\nCHAIN OBJECTIVE — {objective['name'].upper()}: "
        f"{objective['description']} "
        f"Required path: {objective['display']}. "
        f"Report these IN ORDER for maximum bonus. "
        f"Bonus: +{objective['bonus_complete']} complete, "
        f"+{objective['bonus_ordered']} ordered, "
        f"+{objective['bonus_fast_start']} fast start (within 5 steps)."
    )

def matches_chain_step(file: str, vuln_type: str, objective: dict) -> dict | None:
    """Check if a finding matches any step in the chain objective.

    Returns the matching step dict or None.
    Uses _types_match() so aliases work (e.g. 'Timing Side Channel' matches 'Timing Attack').
    """
    if objective is None:
        return None
    for step in objective["steps"]:
        if step["file"] == file and _types_match(vuln_type, step["type"]):
            return step
    return None