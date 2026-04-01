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
    """Normalize a vulnerability type string for comparison.

    Lowercases, replaces underscores/hyphens with spaces, and strips whitespace.
    """
    return raw.lower().replace("_", " ").replace("-", " ").strip()

def _types_match(finding_type: str, gt_type: str) -> bool:
    """Check if a finding type matches a ground truth type.

    Uses exact normalized match first, then falls back to alias lookup.
    """
    norm_finding = normalize_vuln_type(finding_type)
    norm_gt = normalize_vuln_type(gt_type)

    # Direct match
    if norm_finding == norm_gt:
        return True

    # Alias match: check if the finding's type is in the GT type's alias list
    gt_aliases = TYPE_ALIASES.get(norm_gt, [])
    if norm_finding in gt_aliases:
        return True

    return False

def find_matching_ground_truth(
    finding: Finding, ground_truth: list[dict]
) -> dict | None:
    """Find the best matching ground truth entry for a finding.

    Match criteria: type matches (with aliases) AND file matches.
    Returns the matching GT entry or None if it's a false positive.
    """
    for gt_entry in ground_truth:
        gt_file = gt_entry["file"]

        # File must match exactly
        if finding.file != gt_file:
            continue

        # Type must match (exact or via alias)
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
    """Compute a bonus for security-relevant analysis notes.

    Returns +0.05 if any notes contain security reasoning keywords.
    Only applied in Task 3.
    """
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
    """Count previous reports that did not match any ground-truth entry."""
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
    """Compute evidence quality bonus/penalty for report payloads.

    Only applies when evidence mode is enabled.
    """
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

    # Contradiction heuristic: reporting exploitation while reason says it is safe.
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
    """Compute reward for a single vulnerability report.

    Returns (reward_float, breakdown_dict).

    Reward components:
        True positive base:      +0.3
        Line within ±3:          +0.1   (Fix 7: was ±2, now ±3 for consistency)
        Fix quality keywords:    +0.1
        Severity match (task 3): +0.1
        False positive:          -0.1
        Duplicate:                0.0   (env.py overrides this to -0.05)
    """
    breakdown = {
        "type_match": 0.0,
        "line_bonus": 0.0,
        "fix_bonus": 0.0,
        "severity_bonus": 0.0,
        "evidence_bonus": 0.0,
        "false_positive": 0.0,
        "duplicate_penalty": 0.0,
    }

    # Check for duplicate: same file + matching type already reported
    for prev in already_found:
        if (
            prev.file == finding.file
            and _types_match(prev.vulnerability_type, finding.vulnerability_type)
        ):
            breakdown["duplicate_penalty"] = 0.0
            return 0.0, breakdown

    # Try to match against ground truth
    match = find_matching_ground_truth(finding, ground_truth)

    if match is None:
        # False positive
        fp_penalty = -0.1
        if ENABLE_ANTI_GAMING_ESCALATION:
            prior_false_positives = _count_false_positives(already_found, ground_truth)
            if prior_false_positives >= 2:
                fp_penalty = -0.15
            elif prior_false_positives >= 1:
                fp_penalty = -0.12
        breakdown["false_positive"] = fp_penalty
        return fp_penalty, breakdown

    # True positive — base reward
    breakdown["type_match"] = 0.3
    reward = 0.3

    # Fix 7: Line number bonus — standardized to ±3 (was ±2)
    if abs(finding.line_number - match["line"]) <= LINE_TOLERANCE:
        breakdown["line_bonus"] = 0.1
        reward += 0.1

    # Fix quality bonus
    if _has_fix_quality(finding.suggested_fix):
        breakdown["fix_bonus"] = 0.1
        reward += 0.1

    # Severity bonus (task 3 only)
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

def compute_episode_score(
    findings: list[Finding],
    ground_truth: list[dict],
    task_id: int,
    notes: list[str] | None = None,
    current_step: int = 0,
    max_steps: int | None = None,
    chain_bonus: float = 0.0,
    use_precision_scoring: bool = False,
    # Legacy aliases — kept for backward compat with old call sites
    steps_used: int | None = None,
) -> float:
    """Compute the final normalized score for a complete episode.

    max_possible = len(ground_truth) * max_per_finding
    raw = sum of per-finding rewards (each clamped at 0)
    score = clamp(raw / max_possible, 0.0, 1.0)

    Early completion bonus (+0.05) awarded when agent finishes
    in ≤50% of max_steps AND finds ALL vulnerabilities.
    Encourages efficient, precise scanning over step-burning.
    """
    if not ground_truth:
        return 0.0

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

    # Notes quality bonus for Task 3
    if task_id == 3 and notes:
        total_reward += compute_notes_bonus(notes)

    # Resolve step count (current_step takes priority over legacy steps_used)
    effective_step = steps_used if steps_used is not None else current_step

    # Early completion bonus — only if ALL vulnerabilities found AND ≤50% steps used
    if (
        max_steps is not None
        and max_steps > 0
        and effective_step <= max_steps * 0.5
        and true_positive_count >= len(ground_truth)
    ):
        total_reward += 0.05

    # Chain bonus (passed from env.py _handle_mark_complete)
    total_reward += chain_bonus

    if use_precision_scoring:
        precision = true_positive_count / max(1, len(findings))
        precision_bonus = 0.1 * precision
        total_reward += precision_bonus

    return max(0.0, min(1.0, total_reward / max_possible))