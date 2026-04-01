"""
Reward Computation
Pure functions for computing step-level and episode-level rewards.
No state, no side effects — same inputs always produce same outputs.
"""

import re

from environment.models import Finding, VulnerabilityType
from environment.config import (
    ENABLE_ANTI_GAMING_ESCALATION,
    ENABLE_EVIDENCE_MODE,
)

#Vulnerability Type Aliases
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
        "xml injection", "external entity injection",
        "xml external entity injection", "entity injection",
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

#Utility Functions
def normalize_vuln_type(raw: str) -> str:
    s = raw.lower().replace("_", " ").replace("-", " ").strip()
    # Strip trailing parentheticals: "XXE Injection (via ET.parse)" -> same bucket
    s = re.sub(r"\s*\([^)]*\)\s*$", "", s).strip()
    return s

def _types_match(finding_type: str, gt_type: str) -> bool:
    norm_finding = normalize_vuln_type(finding_type)
    norm_gt = normalize_vuln_type(gt_type)

    if norm_finding == norm_gt:
        return True

    canon_f = VulnerabilityType.normalize(finding_type)
    canon_g = VulnerabilityType.normalize(gt_type)
    if canon_f is not None and canon_g is not None and canon_f == canon_g:
        return True
    if canon_f is not None and canon_f.value.lower() == norm_gt:
        return True
    if canon_g is not None and canon_g.value.lower() == norm_finding:
        return True

    gt_aliases = TYPE_ALIASES.get(norm_gt, [])
    if norm_finding in gt_aliases:
        return True

    return False

def _normalize_filename(name: str) -> str:
    """Case-insensitive path compare for LLM output vs ground truth."""
    return name.strip().replace("\\", "/").lower()

def find_matching_ground_truth(
    finding: Finding, ground_truth: list[dict]
) -> dict | None:
    f_file = _normalize_filename(finding.file)
    for gt_entry in ground_truth:
        if f_file != _normalize_filename(gt_entry["file"]):
            continue

        if _types_match(finding.vulnerability_type, gt_entry["type"]):
            return gt_entry

    return None

#Fix Quality
FIX_KEYWORDS = [
    "parameter", "parameterized", "sanitize", "validate", "whitelist",
    "prepared statement", "bcrypt", "argon2", "scrypt",
    "escape", "encode", "restrict", "disable", "remove",
]

def _has_fix_quality(suggested_fix: str) -> bool:
    fix_lower = suggested_fix.lower()
    return any(kw in fix_lower for kw in FIX_KEYWORDS)

#Notes Quality
NOTES_SECURITY_KEYWORDS = [
    "attack", "vulnerability", "exploit", "risk",
    "impact", "threat", "bypass", "exposure",
]

def compute_notes_bonus(notes: list[str]) -> float:
    if not notes:
        return 0.0

    for note in notes:
        note_lower = note.lower()
        if any(kw in note_lower for kw in NOTES_SECURITY_KEYWORDS):
            return 0.05

    return 0.0

#Evidence Quality
GENERIC_EVIDENCE_TOKENS = {"generic", "unknown", "n/a", "none", "safe"}

def _is_low_quality_evidence(value: str | None) -> bool:
    if not value:
        return True

    cleaned = value.strip().lower()
    return len(cleaned) < 10 or cleaned in GENERIC_EVIDENCE_TOKENS

def compute_evidence_score(finding: Finding) -> float:
    if not ENABLE_EVIDENCE_MODE:
        return 0.0

    score = 0.0

    if not _is_low_quality_evidence(finding.data_flow_source):
        score += 0.05

    if not _is_low_quality_evidence(finding.sink):
        score += 0.05

    if not _is_low_quality_evidence(finding.exploitability_reason):
        score += 0.05

    return score

#Step Reward
LINE_TOLERANCE = 3

def compute_step_reward(
    finding: Finding,
    ground_truth: list[dict],
    task_id: int,
    already_found: list[Finding],
) -> tuple[float, dict]:

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
            return 0.0, breakdown

    match = find_matching_ground_truth(finding, ground_truth)

    if match is None:
        penalty = -0.1
        breakdown["false_positive"] = penalty
        return penalty, breakdown

    reward = 0.3
    breakdown["type_match"] = 0.3

    if abs(finding.line_number - match["line"]) <= LINE_TOLERANCE:
        reward += 0.1
        breakdown["line_bonus"] = 0.1

    if _has_fix_quality(finding.suggested_fix):
        reward += 0.1
        breakdown["fix_bonus"] = 0.1

    if task_id == 3:
        if finding.severity.lower() == match["severity"].lower():
            reward += 0.1
            breakdown["severity_bonus"] = 0.1

    evidence_bonus = compute_evidence_score(finding)

    reward += evidence_bonus
    breakdown["evidence_bonus"] = evidence_bonus

    return reward, breakdown

#Chain Bonus
CHAIN_PATTERNS = [
    ["sql injection", "broken authentication"],
    ["idor", "mass assignment"],
    ["jwt misconfiguration", "timing attack", "idor"],
]

def compute_chain_bonus(findings: list[Finding]) -> float:

    discovered = {normalize_vuln_type(f.vulnerability_type) for f in findings}

    bonus = 0.0

    for chain in CHAIN_PATTERNS:
        if all(step in discovered for step in chain):
            bonus += 0.1

    return bonus

def _precision_gated_chain_bonus(
    findings: list[Finding],
    true_positive_count: int,
    min_precision: float = 0.35,
) -> float:
    """
    Apply exploit-chain bonus only when report precision is reasonable.
    Prevents chain-bonus gaming via low-quality finding spam.
    """
    if not findings:
        return 0.0

    precision = true_positive_count / max(1, len(findings))
    if precision < min_precision:
        return 0.0

    return compute_chain_bonus(findings)

#Triage Priority Bonus
SEVERITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

def compute_triage_bonus(findings: list[Finding]) -> float:

    if not findings:
        return 0.0

    ordered = [SEVERITY_WEIGHT.get(f.severity.lower(), 1) for f in findings]

    if ordered == sorted(ordered, reverse=True):
        return 0.05

    return 0.0

#Episode Score
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

    if not ground_truth:
        return 0.0

    max_per_finding = 0.6 if task_id == 3 else 0.5
    max_possible = len(ground_truth) * max_per_finding

    total_reward = 0.0
    seen: list[Finding] = []
    true_positive_count = 0

    for finding in findings:

        step_reward, _ = compute_step_reward(
            finding,
            ground_truth,
            task_id,
            seen,
        )

        total_reward += max(0.0, step_reward)

        if step_reward > 0:
            true_positive_count += 1

        seen.append(finding)

    if task_id == 3 and notes:
        total_reward += compute_notes_bonus(notes)

    # exploit chain reasoning bonus (precision-gated).
    # Use the stronger of:
    # 1) externally computed chain bonus (state-manager chain logic), and
    # 2) local type-pattern chain bonus.
    gated_chain_bonus = _precision_gated_chain_bonus(findings, true_positive_count)
    total_reward += max(chain_bonus, gated_chain_bonus)

    # triage prioritization bonus
    total_reward += compute_triage_bonus(findings)

    effective_step = steps_used if steps_used is not None else current_step

    if (
        max_steps
        and effective_step <= max_steps * 0.5
        and true_positive_count >= len(ground_truth)
    ):
        total_reward += 0.05

    if use_precision_scoring:
        precision = true_positive_count / max(1, len(findings))
        total_reward += 0.1 * precision

    return max(0.0, min(1.0, total_reward / max_possible))