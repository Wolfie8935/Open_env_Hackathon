"""
State Manager
Holds all mutable episode state. Only env.py should call into this.
"""

import re
from typing import Optional

from environment.models import Finding, EpisodeState


# ─── Cascading Discovery Triggers (Fix 1) ─────────────────────
DISCOVERY_TRIGGERS: dict[tuple[str, str], dict] = {
    # Task 2
    ("app.py", "Path Traversal"): {
        "insight": "Path traversal in app.py — session handler in utils.py uses same input flow. Check how cookies reach filesystem.",
        "flag": "utils.py"
    },
    ("utils.py", "Insecure Deserialization"): {
        "insight": "Pickle + path traversal = full RCE chain. Attacker writes malicious pickle then triggers load.",
        "flag": None
    },
    ("config.py", "CORS Misconfiguration"): {
        "insight": "Open CORS + credentials = any website can make auth requests. Check app.py for missing @login_required.",
        "flag": "app.py"
    },
    ("models.py", "Weak Cryptography"): {
        "insight": "MD5 passwords + open CORS = offline cracking after any data leak. Check authentication flow.",
        "flag": None
    },
    ("app.py", "Broken Authentication"): {
        "insight": "No auth on admin endpoint + MD5 hashing = credentials stolen → instant admin access.",
        "flag": None
    },
    # Task 3
    ("config.py", "JWT Misconfiguration"): {
        "insight": "Hardcoded JWT secret = any token forgeable. Check auth.py verify_token() for additional weaknesses.",
        "flag": "auth.py"
    },
    ("config.py", "Debug Mode"): {
        "insight": "DEBUG=True exposes stack traces. Any injection vulnerability becomes RCE via debug console.",
        "flag": None
    },
    ("auth.py", "Timing Attack"): {
        "insight": "== comparison + forged JWT = attacker can enumerate valid tokens. Check views.py endpoints.",
        "flag": "views.py"
    },
    ("views.py", "SSRF"): {
        "insight": "SSRF in webhook handler. Check serializers.py for user-provided URLs in data validation.",
        "flag": "serializers.py"
    },
    ("views.py", "IDOR"): {
        "insight": "IDOR + JWT forgery = forge token for any user ID + access their data. Full account takeover.",
        "flag": None
    },
    ("serializers.py", "Mass Assignment"): {
        "insight": "Mass assignment + IDOR = access any account then escalate their privileges.",
        "flag": None
    },
    ("middleware.py", "XXE Injection"): {
        "insight": "XXE reads server files. DEBUG=True means file contents appear in error stack traces.",
        "flag": None
    },
}

ATTACK_CHAINS = [
    {
        "name": "Full RCE Chain",
        "requires": [("app.py", "Path Traversal"), ("utils.py", "Insecure Deserialization")],
        "bonus": 0.06,
    },
    {
        "name": "Cross-Origin Admin Takeover",
        "requires": [("config.py", "CORS Misconfiguration"), ("app.py", "Broken Authentication")],
        "bonus": 0.05,
    },
    {
        "name": "Complete Account Takeover",
        "requires": [("config.py", "JWT Misconfiguration"), ("auth.py", "Timing Attack"), ("views.py", "IDOR")],
        "bonus": 0.08,
    },
    {
        "name": "Privilege Escalation",
        "requires": [("views.py", "IDOR"), ("serializers.py", "Mass Assignment")],
        "bonus": 0.05,
    },
    {
        "name": "Debug-Amplified XXE",
        "requires": [("config.py", "Debug Mode"), ("middleware.py", "XXE Injection")],
        "bonus": 0.04,
    },
]

# ─── Static scan patterns for Task 2 (Fix 3) ──────────────────
_DANGEROUS_PATTERNS = [
    (r'pickle\.loads', 'insecure_deserialization'),
    (r'eval\(', 'command_injection_candidate'),
    (r'os\.path\.join.*request', 'path_traversal_candidate'),
    (r'hashlib\.md5', 'weak_cryptography'),
    (r'==\s*(token|secret|password|key)', 'timing_attack_candidate'),
    (r'ET\.parse|ElementTree\.parse', 'xxe_candidate'),
    (r'requests\.get\(.*\)', 'network_request'),
    (r'DEBUG\s*=\s*True', 'debug_mode'),
]


class StateManager:
    """Manages mutable state for a single episode."""

    def __init__(self):
        self.task = None
        self.step_number: int = 0
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.visible_files: set[str] = set()
        self.is_complete: bool = False
        self.cumulative_reward: float = 0.0
        # Cascading discovery state (Fix 1)
        self.active_insights: list[str] = []
        self.suspicious_files: list[str] = []
        self.true_positive_keys: list[tuple[str, str]] = []
        self.chains_completed: list[str] = []
        # File reveal tracking (Fix 3)
        self.initial_file_contents: dict[str, str] = {}
        self.revealed_files: set[str] = set()

    def initialize(self, task) -> None:
        """Reset all state for a new episode with the given task."""
        self.task = task
        self.step_number = 0
        self.findings = []
        self.notes = []
        initial = task.get_initial_files()
        self.visible_files = set(initial.keys())
        self.initial_file_contents = dict(initial)
        self.revealed_files = set()
        self.is_complete = False
        self.cumulative_reward = 0.0
        self.active_insights = []
        self.suspicious_files = []
        self.true_positive_keys = []
        self.chains_completed = []

    def add_finding(self, finding: Finding) -> None:
        """Record a new vulnerability finding."""
        self.findings.append(finding)

    def add_note(self, note: str) -> None:
        """Record an analysis note."""
        self.notes.append(note)

    def reveal_file(self, filename: str) -> bool:
        """Make a hidden file visible to the agent.

        Returns True if the file was newly revealed, False if already
        visible or not found in the task.
        For Task 3: re-requesting an initially-visible file upgrades
        it from skeleton to full content.
        """
        if self.task is None:
            return False

        # Task 3 skeleton upgrade: file is visible but only as skeleton
        if filename in self.visible_files and filename not in self.revealed_files:
            if filename in self.initial_file_contents:
                self.revealed_files.add(filename)
                return True

        if filename in self.visible_files:
            return False

        if filename in self.task.files:
            self.visible_files.add(filename)
            self.revealed_files.add(filename)
            return True

        return False

    def increment_step(self) -> None:
        """Advance the step counter. Ends episode if max_steps reached."""
        self.step_number += 1
        if self.task and self.step_number >= self.task.max_steps:
            self.is_complete = True

    def get_visible_file_contents(self) -> dict[str, str]:
        """Return contents of all currently visible files.

        Task 2 revealed files: prepend static scan hints.
        Task 3 initial files: show skeleton until explicitly requested.
        """
        if self.task is None:
            return {}

        result = {}
        for fname in self.visible_files:
            if fname not in self.task.files:
                continue

            # Task 3: show skeleton for initially-visible files not yet requested
            if (self.task.task_id == 3
                    and fname in self.initial_file_contents
                    and fname not in self.revealed_files):
                result[fname] = self.initial_file_contents[fname]
                continue

            content = self.task.files[fname]

            # Task 2: prepend static scan summary for revealed files
            if self.task.task_id == 2 and fname in self.revealed_files:
                hints = self._get_static_hints(fname, content)
                if hints:
                    header = f"# [STATIC SCAN RESULTS FOR {fname}]\n"
                    header += "\n".join(
                        f"# ⚠️  Line {h['line']}: {h['type']}" for h in hints
                    )
                    header += "\n# [END SCAN — review manually for confirmation]\n\n"
                    content = header + content

            result[fname] = content
        return result

    def get_available_files(self) -> list[str]:
        """Return list of all files that can be requested."""
        if self.task is None:
            return []
        available = [f for f in self.task.files.keys() if f not in self.visible_files]
        # Task 3: also list initially-visible files not yet fully revealed
        if self.task and self.task.task_id == 3:
            for f in self.visible_files:
                if f in self.initial_file_contents and f not in self.revealed_files:
                    if f not in available:
                        available.append(f)
        return available

    # ─── Cascading Discovery (Fix 1) ──────────────────────────

    def process_trigger(self, file: str, vuln_type: str) -> Optional[str]:
        """Check if a true positive finding unlocks an insight."""
        key = (file, vuln_type)
        self.true_positive_keys.append(key)
        trigger = DISCOVERY_TRIGGERS.get(key)
        if not trigger:
            return None
        insight = trigger["insight"]
        if insight not in self.active_insights:
            self.active_insights.append(insight)
        if trigger["flag"] and trigger["flag"] not in self.suspicious_files:
            self.suspicious_files.append(trigger["flag"])
        return insight

    def compute_chain_bonuses(self) -> tuple[float, list[str]]:
        """Compute bonus score for discovered attack chains."""
        found = set(self.true_positive_keys)
        total = 0.0
        completed = []
        # Only give chain bonus if precision is reasonable
        total_reports = max(1, len(self.findings))
        true_pos = len(self.true_positive_keys)
        if true_pos / total_reports < 0.35:
            return 0.0, []
        for chain in ATTACK_CHAINS:
            if set(tuple(r) for r in chain["requires"]).issubset(found):
                total += chain["bonus"]
                completed.append(chain["name"])
        return min(total, 0.15), completed

    # ─── Static Scan Hints for Task 2 (Fix 3) ────────────────

    def _get_static_hints(self, fname: str, content: str) -> list[dict]:
        """Simple regex-based hints — no LLM, zero API calls."""
        hints = []
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, hint_type in _DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    hints.append({'line': i, 'type': hint_type})
                    break
        return hints[:3]  # max 3 hints per file

    def to_state_dict(self) -> dict:
        """Return full episode state as a dictionary."""
        return EpisodeState(
            task_id=self.task.task_id if self.task else 0,
            step_number=self.step_number,
            max_steps=self.task.max_steps if self.task else 0,
            findings=self.findings,
            notes=self.notes,
            visible_files=sorted(self.visible_files),
            all_files=sorted(self.task.files.keys()) if self.task else [],
            is_complete=self.is_complete,
            cumulative_reward=self.cumulative_reward,
        ).model_dump()
