"""
Reward Computation
Pure functions for computing step-level and episode-level rewards.
No state, no side effects — same inputs always produce same outputs.
"""

from environment.models import Finding
from environment.config import (
    ENABLE_ANTI_GAMING_ESCALATION,
    ENABLE_EVIDENCE_MODE,
)

STRICT_SCORE_EPS = 0.01


def _clamp_open_01(score: float) -> float:
    """Clamp to open interval (0, 1) for validator compatibility.

    eps=0.01 ensures that after 2-decimal formatting the score string
    can never be "0.00" or "1.00" — the evaluator rejects both boundary
    values.
    """
    return max(STRICT_SCORE_EPS, min(1.0 - STRICT_SCORE_EPS, float(score)))

#Type Alias Map
TYPE_ALIASES: dict[str, list[str]] = {
    "hardcoded secret": [
        "hardcoded secret", "jwt misconfiguration", "jwt secret hardcoded",
        "hardcoded key", "hardcoded password", "hardcoded api key",
        "hardcoded token", "hard coded secret",
    ],
    "jwt misconfiguration": [
        "jwt misconfiguration", "hardcoded secret", "hardcoded jwt",
        "jwt secret", "jwt weak secret", "hardcoded key",
    ],
    "weak cryptography": [
        "weak cryptography", "timing attack", "insecure comparison",
        "weak hash", "insecure hash", "weak crypto",
    ],
    "timing attack": [
        "timing attack", "weak cryptography", "insecure comparison",
        "side channel", "timing side channel",
    ],
    "command injection": [
        "command injection", "code injection", "eval injection",
        "remote code execution", "rce",
    ],
    "broken authentication": [
        "broken authentication", "missing authentication", "broken auth",
        "authentication bypass", "missing auth",
    ],
    "insecure deserialization": [
        "insecure deserialization", "unsafe deserialization",
        "pickle deserialization", "deserialization",
    ],
    "debug mode": [
        "debug mode", "debug mode in production", "debug enabled",
    ],
    "debug mode in production": [
        "debug mode in production", "debug mode", "debug enabled",
    ],
    "xxe injection": [
        "xxe injection", "xxe", "xml external entity",
        "xml injection",
    ],
    "mass assignment": [
        "mass assignment", "attribute injection", "mass",
    ],
    "idor": [
        "idor", "insecure direct object reference",
        "insecure direct object", "direct object reference",
    ],
    "ssrf": [
        "ssrf", "server side request forgery",
        "server side request",
    ],
    "cors misconfiguration": [
        "cors misconfiguration", "cors", "cross origin",
    ],
    "path traversal": [
        "path traversal", "directory traversal", "file traversal",
        "local file inclusion", "lfi",
    ],
    "sql injection": [
        "sql injection", "sqli", "sql",
    ],
}

def normalize_vuln_type(raw: str) -> str:
    """Normalize a vulnerability type string for comparison."""
    return raw.lower().replace("_", " ").replace("-", " ").strip()

def _types_match(finding_type: str, gt_type: str) -> bool:
    """Check if a finding type matches a ground truth type."""
    norm_finding = normalize_vuln_type(finding_type)
    norm_gt = normalize_vuln_type(gt_type)

    if norm_finding == norm_gt:
        return True

    gt_aliases = TYPE_ALIASES.get(norm_gt, [])
    if norm_finding in gt_aliases:
        return True

    return False

def find_matching_ground_truth(
    finding: Finding, ground_truth: list[dict]
) -> dict | None:
    """Find the best matching ground truth entry for a finding."""
    for gt_entry in ground_truth:
        gt_file = gt_entry["file"]

        if finding.file != gt_file:
            continue

        if _types_match(finding.vulnerability_type, gt_entry["type"]):
            return gt_entry

    return None

#Fix Quality Keywords
FIX_KEYWORDS = [
    "parameter", "parameterized", "environ", "environment variable",
    "sanitize", "sanitiz", "whitelist", "allowlist", "validate",
    "digest", "compare_digest", "hmac", "defused", "defusedxml",
    "literal_eval", "bcrypt", "argon2", "scrypt", "prepared statement",
    "escap", "encod", "restrict", "disable", "remove", "replace",
    "secret manager", "vault", "rotate", "jwt secret", "false",
    "secure_filename", "basename", "login_required", "auth",
    "json.loads", "verify", "check", "block", "realpath",
    "subprocess", "shlex", "quote",
]

def _has_fix_quality(suggested_fix: str) -> bool:
    """Check if a suggested fix contains meaningful security keywords."""
    fix_lower = suggested_fix.lower()
    return any(kw in fix_lower for kw in FIX_KEYWORDS)

#Notes Quality 
NOTES_SECURITY_KEYWORDS = [
    "attack", "vulnerability", "vulnerabilities", "exploit", "risk",
    "impact", "threat", "injection", "bypass", "unauthorized",
    "authentication", "authorization", "sensitive", "exposure",
    "traversal", "deserialization", "hardcoded", "secret",
]

def compute_notes_bonus(notes: list[str]) -> float:
    """Compute a bonus for security-relevant analysis notes."""
    if not notes:
        return 0.0

    for note in notes:
        note_lower = note.lower()
        if any(kw in note_lower for kw in NOTES_SECURITY_KEYWORDS):
            return 0.05

    return 0.0

#Line Tolerance
LINE_TOLERANCE = 3
GENERIC_EVIDENCE_TOKENS = {"generic", "unknown", "n/a", "none", "safe", "not sure"}

def _count_false_positives(findings: list[Finding], ground_truth: list[dict]) -> int:
    return sum(
        1
        for prev in findings
        if find_matching_ground_truth(prev, ground_truth) is None
    )

def _is_low_quality_evidence(value: str | None) -> bool:
    if not value:
        return True
    cleaned = value.strip().lower()
    return len(cleaned) < 10 or cleaned in GENERIC_EVIDENCE_TOKENS

def compute_evidence_score(finding: Finding) -> float:
    """Compute evidence quality bonus/penalty for report payloads."""
    if not ENABLE_EVIDENCE_MODE:
        return 0.0

    fields = {
        "source": finding.data_flow_source,
        "sink": finding.sink,
        "reason": finding.exploitability_reason,
    }

    source_ok = not _is_low_quality_evidence(fields["source"])
    sink_ok = not _is_low_quality_evidence(fields["sink"])
    reason_ok = not _is_low_quality_evidence(fields["reason"])

    score = 0.0
    if source_ok:
        score += 0.05
    if sink_ok:
        score += 0.05
    if reason_ok:
        score += 0.05

    reason = (fields["reason"] or "").lower()
    if any(token in reason for token in ("safe", "not exploitable", "no risk")):
        score -= 0.05

    return score

def compute_step_reward(
    finding: Finding,
    ground_truth: list[dict],
    task_id: int,
    already_found: list[Finding],
) -> tuple[float, dict]:
    """Compute reward for a single vulnerability report."""
    breakdown = {
        "type_match": 0.0,
        "line_bonus": 0.0,
        "fix_bonus": 0.0,
        "severity_bonus": 0.0,
        "evidence_bonus": 0.0,
        "false_positive": 0.0,
        "duplicate_penalty": 0.0,
    }

    for prev in already_found:
        if (
            prev.file == finding.file
            and _types_match(prev.vulnerability_type, finding.vulnerability_type)
        ):
            breakdown["duplicate_penalty"] = 0.0
            return 0.0, breakdown

    match = find_matching_ground_truth(finding, ground_truth)

    if match is None:
        fp_penalty = -0.1
        if ENABLE_ANTI_GAMING_ESCALATION:
            prior_false_positives = _count_false_positives(already_found, ground_truth)
            if prior_false_positives >= 2:
                fp_penalty = -0.15
            elif prior_false_positives >= 1:
                fp_penalty = -0.12
        breakdown["false_positive"] = fp_penalty
        return fp_penalty, breakdown

    breakdown["type_match"] = 0.3
    reward = 0.3

    if abs(finding.line_number - match["line"]) <= LINE_TOLERANCE:
        breakdown["line_bonus"] = 0.1
        reward += 0.1

    if _has_fix_quality(finding.suggested_fix):
        breakdown["fix_bonus"] = 0.1
        reward += 0.1

    if task_id == 3:
        finding_sev = finding.severity.lower().strip()
        gt_sev = match["severity"].lower().strip()
        if finding_sev == gt_sev:
            breakdown["severity_bonus"] = 0.1
            reward += 0.1

    evidence_bonus = compute_evidence_score(finding)
    if evidence_bonus:
        breakdown["evidence_bonus"] = evidence_bonus
        reward += evidence_bonus

    return reward, breakdown

#Triage Scoring
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 3.0,
    "high":     2.0,
    "medium":   1.0,
    "low":      0.5,
}

def _get_severity_weight(severity: str) -> float:
    return SEVERITY_WEIGHTS.get(severity.lower().strip(), 1.0)

def compute_triage_score(
    findings: list[Finding],
    ground_truth: list[dict],
    steps_used: int,
    max_steps: int,
) -> tuple[float, dict]:
    """Compute triage score: weighted_recall × prioritization_quality × step_efficiency.

    weighted_recall: rewards finding Critical (3×) before High (2×) before Medium (1×).
    prioritization_quality: penalises reporting Medium before unreported Critical.
    step_efficiency: full credit at ≤60% budget, degrades linearly after.
    """
    if not ground_truth or steps_used == 0:
        return 0.0, {}

    # Weighted recall
    gt_total_weight = sum(
        _get_severity_weight(gt.get("severity", "medium")) for gt in ground_truth
    )
    if gt_total_weight == 0:
        gt_total_weight = 1.0

    true_positive_weight = 0.0
    for finding in findings:
        match = find_matching_ground_truth(finding, ground_truth)
        if match is not None:
            true_positive_weight += _get_severity_weight(match.get("severity", "medium"))

    weighted_recall = min(1.0, true_positive_weight / gt_total_weight)

    # Prioritization quality
    tp_findings = [
        f for f in findings
        if find_matching_ground_truth(f, ground_truth) is not None
    ]

    correct_pairs = 0
    wrong_pairs = 0
    for i in range(len(tp_findings)):
        for j in range(i + 1, len(tp_findings)):
            w_i = _get_severity_weight(tp_findings[i].severity)
            w_j = _get_severity_weight(tp_findings[j].severity)
            if w_i >= w_j:
                correct_pairs += 1
            else:
                wrong_pairs += 1

    total_pairs = correct_pairs + wrong_pairs
    prioritization_quality = correct_pairs / total_pairs if total_pairs > 0 else 1.0

    #Step efficiency
    if max_steps > 0:
        step_efficiency = min(1.0, (max_steps * 0.6) / max(1, steps_used))
        step_efficiency = max(0.1, step_efficiency)
    else:
        step_efficiency = 1.0

    triage_score = weighted_recall * prioritization_quality * step_efficiency

    breakdown = {
        "weighted_recall": round(weighted_recall, 4),
        "prioritization_quality": round(prioritization_quality, 4),
        "step_efficiency": round(step_efficiency, 4),
        "correct_pairs": correct_pairs,
        "wrong_pairs": wrong_pairs,
        "triage_score": round(triage_score, 4),
    }

    return round(triage_score, 4), breakdown

def compute_severity_coverage(
    findings: list[Finding],
    ground_truth: list[dict],
) -> dict[str, str]:
    """Return per-severity found/total display strings.

    Example: {"Critical": "2/2", "High": "1/3", "Medium": "0/2"}
    """
    gt_by_sev: dict[str, int] = {}
    for gt in ground_truth:
        sev = gt.get("severity", "Medium")
        gt_by_sev[sev] = gt_by_sev.get(sev, 0) + 1

    found_by_sev: dict[str, int] = {sev: 0 for sev in gt_by_sev}
    for finding in findings:
        match = find_matching_ground_truth(finding, ground_truth)
        if match is not None:
            sev = match.get("severity", "Medium")
            if sev in found_by_sev:
                found_by_sev[sev] += 1

    order = ["Critical", "High", "Medium", "Low"]
    result = {}
    for sev in order:
        if sev in gt_by_sev:
            result[sev] = f"{found_by_sev.get(sev, 0)}/{gt_by_sev[sev]}"

    return result

#Chain Objective Bonus
def compute_chain_objective_bonus(
    chain_complete: bool,
    chain_ordered: bool,
    chain_fast_start: bool,
    non_chain_reports_before_complete: int,
    objective: dict,
) -> tuple[float, dict]:
    """Compute bonus for the chain objective layer.

    Applied once at mark_complete (complete + ordered bonuses).
    fast_start and distraction signals applied live at step time.
    Guard against double-counting is in state_manager.
    """
    if objective is None:
        return 0.0, {}

    bonus = 0.0
    breakdown = {
        "complete_bonus": 0.0,
        "ordered_bonus": 0.0,
        "fast_start_bonus": 0.0,
        "distraction_penalty": 0.0,
    }

    if chain_complete:
        breakdown["complete_bonus"] = objective["bonus_complete"]
        bonus += objective["bonus_complete"]

        if chain_ordered:
            breakdown["ordered_bonus"] = objective["bonus_ordered"]
            bonus += objective["bonus_ordered"]

    if chain_fast_start:
        breakdown["fast_start_bonus"] = objective["bonus_fast_start"]
        bonus += objective["bonus_fast_start"]

    raw_penalty = non_chain_reports_before_complete * objective["penalty_distraction"]
    capped_penalty = max(objective["max_distraction_penalty"], raw_penalty)
    breakdown["distraction_penalty"] = capped_penalty
    bonus += capped_penalty

    return bonus, breakdown

def compute_episode_score(
    findings: list[Finding],
    ground_truth: list[dict],
    task_id: int,
    notes: list[str] | None = None,
    current_step: int = 0,
    max_steps: int | None = None,
    chain_bonus: float = 0.0,
    use_precision_scoring: bool = False,
    steps_used: int | None = None,
) -> float:
    """Compute the final normalized score for a complete episode."""
    if not ground_truth:
        return _clamp_open_01(0.0)

    max_per_finding = 0.6 if task_id == 3 else 0.5
    max_possible = len(ground_truth) * max_per_finding

    total_reward = 0.0
    seen_findings: list[Finding] = []
    true_positive_count = 0

    for finding in findings:
        step_reward, _ = compute_step_reward(
            finding, ground_truth, task_id, seen_findings
        )
        total_reward += max(0.0, step_reward)
        if step_reward > 0:
            true_positive_count += 1
        seen_findings.append(finding)

    if task_id == 3 and notes:
        total_reward += compute_notes_bonus(notes)

    effective_step = steps_used if steps_used is not None else current_step

    if (
        max_steps is not None
        and max_steps > 0
        and effective_step <= max_steps * 0.5
        and true_positive_count >= len(ground_truth)
    ):
        total_reward += 0.05

    total_reward += chain_bonus

    if use_precision_scoring:
        precision = true_positive_count / max(1, len(findings))
        precision_bonus = 0.1 * precision
        total_reward += precision_bonus

    return _clamp_open_01(total_reward / max_possible)