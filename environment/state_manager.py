"""
State Manager
Holds all mutable episode state. Only env.py should call into this.
"""

import re
from typing import Optional

from environment.models import Finding, EpisodeState
from environment.reward import (
    compute_step_reward,
    find_matching_ground_truth,
    compute_notes_bonus,
    _get_severity_weight,
    _clamp_open_01,
)

#Cascading Discovery Triggers
DISCOVERY_TRIGGERS: dict[tuple[str, str], dict] = {
    #Task 2
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
    #Task 3
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

#Static scan patterns for Task 2
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
        #Cascading discovery state
        self.active_insights: list[str] = []
        self.suspicious_files: list[str] = []
        self.true_positive_keys: list[tuple[str, str]] = []
        self.chains_completed: list[str] = []
        #File reveal tracking
        self.initial_file_contents: dict[str, str] = {}
        self.revealed_files: set[str] = set()

        #Chain Objective Layer
        self.chain_objective: Optional[dict] = None
        self.chain_steps_found: list[int] = []        # order numbers found so far
        self.chain_ordered: bool = True               # False once out-of-order step found
        self.chain_complete: bool = False
        self.chain_fast_start: bool = False           # True if step 1 found within 5 env steps
        self.non_chain_before_complete: int = 0       # count of distraction reports
        #Guard: live bonuses (fast_start, distraction) applied once, not again at mark_complete
        self._chain_fast_start_bonus_applied: bool = False
        self._chain_distraction_penalties_applied: int = 0
        #Guard: complete+ordered bonus applied once at mark_complete only
        self._chain_complete_bonus_applied: bool = False

        #Triage Mode
        self.triage_mode: bool = False
        self.triage_max_steps: int = 0

        # ---- Cached derived metrics (event-driven) ----
        # Live chain status cache (derived from true_positive_keys)
        self._live_chain_status_cache: list[dict] = []
        self._live_chain_status_dirty: bool = True

        # Severity coverage cache (derived from matched GT findings)
        self._gt_total_by_sev: dict[str, int] = {}
        self._found_by_sev: dict[str, int] = {}
        self.severity_coverage_cache: dict[str, str] = {}

        # Triage score caches (exactly matches compute_triage_score)
        self._triage_gt_total_weight: float = 1.0
        self._triage_tp_weight_sum: float = 0.0                 # weights from GT severities
        self._triage_correct_pairs: int = 0                      # pairwise ordering quality numerator
        self._triage_wrong_pairs: int = 0                        # pairwise ordering quality denominator part
        self._triage_seen_weight_counts: dict[float, int] = {}   # counts of agent severity weights seen so far (TP only)
        self.triage_score_cache: float = 0.0

        # Episode scoring caches (exactly matches compute_episode_score)
        self._episode_seen_for_scoring: list[Finding] = []
        self._episode_sum_positive_step_rewards: float = 0.0
        self._episode_true_positive_count: int = 0
        self._episode_max_possible: float = 1.0

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

        #Reset chain objective state
        self.chain_objective = None
        self.chain_steps_found = []
        self.chain_ordered = True
        self.chain_complete = False
        self.chain_fast_start = False
        self.non_chain_before_complete = 0
        self._chain_fast_start_bonus_applied = False
        self._chain_distraction_penalties_applied = 0
        self._chain_complete_bonus_applied = False

        #Reset triage state
        self.triage_mode = getattr(task, "triage_mode", False)
        self.triage_max_steps = getattr(task, "triage_max_steps", task.max_steps)

        # Reset caches
        self._live_chain_status_cache = []
        self._live_chain_status_dirty = True

        # Precompute severity totals from GT
        self._gt_total_by_sev = {}
        for gt in getattr(task, "ground_truth", []) or []:
            sev = gt.get("severity", "Medium")
            self._gt_total_by_sev[sev] = self._gt_total_by_sev.get(sev, 0) + 1
        self._found_by_sev = {sev: 0 for sev in self._gt_total_by_sev}
        self.severity_coverage_cache = self._format_severity_coverage_cache()

        # Precompute triage GT weight total
        self._triage_gt_total_weight = sum(
            _get_severity_weight(gt.get("severity", "medium"))
            for gt in getattr(task, "ground_truth", []) or []
        )
        if self._triage_gt_total_weight == 0:
            self._triage_gt_total_weight = 1.0
        self._triage_tp_weight_sum = 0.0
        self._triage_correct_pairs = 0
        self._triage_wrong_pairs = 0
        self._triage_seen_weight_counts = {}
        self.triage_score_cache = 0.0

        # Episode scoring caches
        self._episode_seen_for_scoring = []
        self._episode_sum_positive_step_rewards = 0.0
        self._episode_true_positive_count = 0
        gt_count = len(getattr(task, "ground_truth", []) or [])
        max_per_finding = 0.6 if getattr(task, "task_id", 0) == 3 else 0.5
        self._episode_max_possible = max(1e-9, gt_count * max_per_finding)

    def add_finding(self, finding: Finding) -> None:
        """Record a new vulnerability finding."""
        self.findings.append(finding)
        self._update_cached_metrics_for_new_finding(finding)

    def add_note(self, note: str) -> None:
        """Record an analysis note."""
        self.notes.append(note)

    def reveal_file(self, filename: str) -> bool:
        """Make a hidden file visible to the agent."""
        if self.task is None:
            return False

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
        # Triage step efficiency depends on steps_used, so refresh cache each step (O(1)).
        self._recompute_triage_score_cache()

    def _update_cached_metrics_for_new_finding(self, finding: Finding) -> None:
        """Event-driven cache update when a finding is appended."""
        if self.task is None:
            return

        # Episode scoring: incremental update using the same step reward function.
        step_reward, _ = compute_step_reward(
            finding,
            self.task.ground_truth,
            self.task.task_id,
            self._episode_seen_for_scoring,
        )
        if step_reward > 0:
            self._episode_true_positive_count += 1
        self._episode_sum_positive_step_rewards += max(0.0, step_reward)
        self._episode_seen_for_scoring.append(finding)

        # Match to ground truth once (used by triage + severity coverage).
        match = find_matching_ground_truth(finding, self.task.ground_truth)
        if match is None:
            return

        # Severity coverage: count by GT severity.
        sev = match.get("severity", "Medium")
        if sev in self._found_by_sev:
            self._found_by_sev[sev] += 1
            self.severity_coverage_cache = self._format_severity_coverage_cache()

        # Triage: weighted recall uses GT severity; prioritization uses agent-reported severity for matched TPs.
        self._triage_tp_weight_sum += _get_severity_weight(sev)
        w_new = _get_severity_weight(finding.severity)

        # Update exact pair counts incrementally (same logic as compute_triage_score).
        count_lt = 0
        count_ge = 0
        for w, c in self._triage_seen_weight_counts.items():
            if w < w_new:
                count_lt += c
            else:
                count_ge += c
        self._triage_correct_pairs += count_ge
        self._triage_wrong_pairs += count_lt
        self._triage_seen_weight_counts[w_new] = self._triage_seen_weight_counts.get(w_new, 0) + 1

        self._recompute_triage_score_cache()

    def _format_severity_coverage_cache(self) -> dict[str, str]:
        order = ["Critical", "High", "Medium", "Low"]
        result: dict[str, str] = {}
        for sev in order:
            if sev in self._gt_total_by_sev:
                result[sev] = f"{self._found_by_sev.get(sev, 0)}/{self._gt_total_by_sev[sev]}"
        return result

    def _recompute_triage_score_cache(self) -> None:
        if not self.triage_mode or self.step_number <= 0 or self.task is None:
            self.triage_score_cache = 0.0
            return

        weighted_recall = min(
            1.0,
            self._triage_tp_weight_sum / max(1e-9, self._triage_gt_total_weight),
        )

        total_pairs = self._triage_correct_pairs + self._triage_wrong_pairs
        prioritization_quality = (self._triage_correct_pairs / total_pairs) if total_pairs > 0 else 1.0

        max_steps = max(1, int(self.triage_max_steps))
        steps_used = max(1, int(self.step_number))
        step_efficiency = min(1.0, (max_steps * 0.6) / steps_used)
        step_efficiency = max(0.1, step_efficiency)

        self.triage_score_cache = round(weighted_recall * prioritization_quality * step_efficiency, 4)

    def compute_episode_score_cached(
        self,
        *,
        chain_bonus: float = 0.0,
        use_precision_scoring: bool = False,
        current_step: int = 0,
        max_steps: int | None = None,
    ) -> float:
        """O(1) episode scoring from cached totals (matches compute_episode_score)."""
        if self.task is None or not self.task.ground_truth:
            return _clamp_open_01(0.0)

        total_reward = float(self._episode_sum_positive_step_rewards)

        if self.task.task_id == 3 and self.notes:
            total_reward += compute_notes_bonus(self.notes)

        effective_step = current_step
        if (
            max_steps
            and effective_step <= max_steps * 0.5
            and self._episode_true_positive_count >= len(self.task.ground_truth)
        ):
            total_reward += 0.05

        total_reward += chain_bonus

        if use_precision_scoring:
            precision = self._episode_true_positive_count / max(1, len(self.findings))
            total_reward += 0.1 * precision

        return _clamp_open_01(total_reward / self._episode_max_possible)

    def get_visible_file_contents(self) -> dict[str, str]:
        """Return contents of all currently visible files."""
        if self.task is None:
            return {}

        result = {}
        for fname in self.visible_files:
            if fname not in self.task.files:
                continue

            if (self.task.task_id == 3
                    and fname in self.initial_file_contents
                    and fname not in self.revealed_files):
                result[fname] = self.initial_file_contents[fname]
                continue

            content = self.task.files[fname]

            if self.task.task_id == 2 and fname in self.revealed_files:
                hints = self._get_static_hints(fname, content)
                if hints:
                    header = f"# [STATIC SCAN RESULTS FOR {fname}]\n"
                    header += "\n".join(
                        f"# Line {h['line']}: {h['type']}" for h in hints
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
        if self.task and self.task.task_id == 3:
            for f in self.visible_files:
                if f in self.initial_file_contents and f not in self.revealed_files:
                    if f not in available:
                        available.append(f)
        return available

    #Cascading Discovery
    def process_trigger(self, file: str, vuln_type: str) -> Optional[str]:
        """Check if a true positive finding unlocks an insight."""
        key = (file, vuln_type)
        self.true_positive_keys.append(key)
        self._live_chain_status_dirty = True
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
        """Compute bonus score for discovered ATTACK_CHAINS at mark_complete.

        This is separate from chain_objective bonuses — these are the 5 structural
        chains defined in ATTACK_CHAINS. Precision guard: skip if agent spammed FPs.
        """
        found = set(self.true_positive_keys)
        total = 0.0
        completed = []
        total_reports = max(1, len(self.findings))
        true_pos = len(self.true_positive_keys)
        if true_pos / total_reports < 0.35:
            return 0.0, []
        for chain in ATTACK_CHAINS:
            if set(tuple(r) for r in chain["requires"]).issubset(found):
                total += chain["bonus"]
                completed.append(chain["name"])
        return min(total, 0.15), completed

    #Chain Objective Processing
    def process_chain_step(
        self, file: str, vuln_type: str
    ) -> tuple[float, str]:
        """Check if a true positive matches the active chain objective.

        Called from env.py _handle_report() after a positive reward.
        Returns (live_bonus_float, feedback_addition_string).

        Live bonuses applied here (fast_start, distraction penalty).
        Complete+ordered bonuses deferred to mark_complete to avoid double-count.
        """
        if self.chain_objective is None or self.chain_complete:
            if (
                self.chain_objective is not None
                and not self.chain_complete
            ):
                pass  
            return 0.0, ""

        from environment.chain_objective import matches_chain_step
        matched_step = matches_chain_step(file, vuln_type, self.chain_objective)

        live_bonus = 0.0
        feedback_parts = []

        if matched_step is None:
            self.non_chain_before_complete += 1
            new_penalties = self.non_chain_before_complete - self._chain_distraction_penalties_applied
            if new_penalties > 0:
                obj = self.chain_objective
                max_pen = obj["max_distraction_penalty"]
                already = self._chain_distraction_penalties_applied * obj["penalty_distraction"]
                #Apply only new penalty if not yet at cap
                if already > max_pen:
                    penalty = obj["penalty_distraction"] * new_penalties
                    if (already + penalty) < max_pen:
                        penalty = max_pen - already
                    live_bonus += penalty
                    self._chain_distraction_penalties_applied += new_penalties
                    feedback_parts.append(
                        f"CHAIN DISTRACTION: reported non-chain vuln before completing "
                        f"'{self.chain_objective['name']}'. Penalty: {penalty:.2f}"
                    )
            return live_bonus, " | ".join(feedback_parts)

        #Matched a chain step
        order = matched_step["order"]

        #Check ordering
        if self.chain_steps_found:
            expected_next = max(self.chain_steps_found) + 1
            if order != expected_next:
                self.chain_ordered = False

        if order not in self.chain_steps_found:
            self.chain_steps_found.append(order)

        total_steps = len(self.chain_objective["steps"])
        found_count = len(self.chain_steps_found)

        #Fast start: first chain step found within 5 env steps
        if found_count == 1 and self.step_number <= 5 and not self._chain_fast_start_bonus_applied:
            self.chain_fast_start = True
            self._chain_fast_start_bonus_applied = True
            live_bonus += self.chain_objective["bonus_fast_start"]
            feedback_parts.append(
                f"CHAIN FAST START: found '{matched_step['type']}' within {self.step_number} steps. "
                f"Bonus: +{self.chain_objective['bonus_fast_start']}"
            )

        #Progress feedback
        remaining = [
            s for s in self.chain_objective["steps"]
            if s["order"] not in self.chain_steps_found
        ]
        if remaining:
            next_step = min(remaining, key=lambda s: s["order"])
            feedback_parts.append(
                f"CHAIN PROGRESS ({found_count}/{total_steps}): "
                f"next → {next_step['type']} in {next_step['file']}"
            )
        else:
            #Chain complete
            self.chain_complete = True
            feedback_parts.append(
                f"⚡ CHAIN COMPLETE: '{self.chain_objective['name']}' "
                f"({'ordered' if self.chain_ordered else 'unordered'}). "
                f"Full bonus applied at mark_complete."
            )

        return live_bonus, " | ".join(feedback_parts)

    def get_chain_objective_bonus_for_mark_complete(self) -> float:
        """Compute and return the complete+ordered chain objective bonus.

        Called once at mark_complete. Guards against double-counting.
        """
        if self._chain_complete_bonus_applied or self.chain_objective is None:
            return 0.0

        self._chain_complete_bonus_applied = True

        from environment.reward import compute_chain_objective_bonus
        bonus, _ = compute_chain_objective_bonus(
            chain_complete=self.chain_complete,
            chain_ordered=self.chain_ordered,
            chain_fast_start=self.chain_fast_start,
            non_chain_reports_before_complete=self.non_chain_before_complete,
            objective=self.chain_objective,
        )
        #Subtract already-applied live bonuses to avoid double-counting
        already_applied = 0.0
        if self.chain_fast_start and self._chain_fast_start_bonus_applied:
            already_applied += self.chain_objective["bonus_fast_start"]
        already_applied += (
            self._chain_distraction_penalties_applied
            * self.chain_objective["penalty_distraction"]
        )
        return bonus - already_applied

    #Live Chain Status
    def get_live_chain_status(self) -> list[dict]:
        """Return current completion status of all ATTACK_CHAINS.

        Shown to agent every step in observation.live_chain_status.
        This gives the agent live signal about which structural chains
        it is close to completing — rewarding reasoning over grep.
        """
        if not self._live_chain_status_dirty:
            return self._live_chain_status_cache

        found = set(self.true_positive_keys)
        status: list[dict] = []
        for chain in ATTACK_CHAINS:
            required = set(tuple(r) for r in chain["requires"])
            found_steps = required.intersection(found)
            remaining = list(required - found_steps)
            complete = required.issubset(found)
            status.append({
                "name": chain["name"],
                "found": len(found_steps),
                "total": len(required),
                "complete": complete,
                "bonus": chain["bonus"],
                "remaining": [{"file": r[0], "type": r[1]} for r in remaining],
                "progress_str": (
                    f"{len(found_steps)}/{len(required)} — BONUS EARNED (+{chain['bonus']})"
                    if complete
                    else f"{len(found_steps)}/{len(required)}"
                ),
            })

        self._live_chain_status_cache = status
        self._live_chain_status_dirty = False
        return status

    #Static Scan Hints for Task 2
    def _get_static_hints(self, fname: str, content: str) -> list[dict]:
        """Simple regex-based hints — no LLM, zero API calls."""
        hints = []
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, hint_type in _DANGEROUS_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    hints.append({'line': i, 'type': hint_type})
                    break
        return hints[:3]

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