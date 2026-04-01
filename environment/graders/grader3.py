"""
Grader 3: Reasoning-Based Rubric
Pure-Python grader evaluating detection, severity, fix specificity,
and methodology documentation. No LLM calls.
"""

from environment.graders.base_grader import BaseGrader
from environment.models import Finding
from environment.reward import _types_match, _has_fix_quality, LINE_TOLERANCE

#Terms that indicate specific, actionable fixes (not generic advice)
SPECIFIC_FIX_TERMS = [
    "parameterized", "prepared statement", "os.environ", "environment variable",
    "bcrypt", "argon2", "hmac.compare_digest", "ast.literal_eval",
    "defusedxml", "whitelist", "allowlist", "os.path.basename",
    "secure_filename", "json.loads", "rate limit", "decorator",
    "@login_required", "csrf", "content security policy",
]

#Terms indicating chain/methodology reasoning
CHAIN_TERMS = [
    "chain", "combined", "leads to", "enables", "together",
    "combined with", "escalat", "pivot", "lateral",
]

#Exploit chain definitions (objective layer)
EXPLOIT_CHAINS = [
    [
        ("config.py", "JWT Misconfiguration"),
        ("auth.py", "Timing Attack"),
        ("views.py", "IDOR"),
    ],
    [
        ("app.py", "Path Traversal"),
        ("utils.py", "Insecure Deserialization"),
    ],
]

#Severity ordering for triage mode
SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

#Fix 7: Additional semantic alias pairs for grader-level matching.
SEMANTIC_PAIRS = [
    ("sqli", "sql injection"),
    ("rce", "command injection"),
    ("lfi", "path traversal"),
    ("directory traversal", "path traversal"),
    ("server side request forgery", "ssrf"),
    ("xml external entity", "xxe injection"),
    ("insecure direct object reference", "idor"),
    ("broken auth", "broken authentication"),
    ("missing auth", "broken authentication"),
    ("debug enabled", "debug mode"),
    ("debug mode in production", "debug mode"),
    ("jwt secret", "jwt misconfiguration"),
    ("hardcoded jwt", "jwt misconfiguration"),
    ("timing side channel", "timing attack"),
    ("pickle deserialization", "insecure deserialization"),
    ("cross origin", "cors misconfiguration"),
]

def _semantic_match(finding_type: str, gt_type: str) -> bool:
    f = finding_type.lower().strip()
    g = gt_type.lower().strip()
    if f == g:
        return True
    for a, b in SEMANTIC_PAIRS:
        if (f == a and g == b) or (f == b and g == a):
            return True
    return False

def _triage_bonus(findings: list[Finding]) -> float:
    """Reward correct vulnerability prioritization."""
    if not findings:
        return 0.0

    ranks = [SEVERITY_ORDER.get((f.severity or "").lower(), 1) for f in findings]

    if ranks == sorted(ranks, reverse=True):
        return 0.05

    return 0.0

def _chain_bonus(findings: list[Finding]) -> float:
    """Reward discovery of multi-step exploit chains."""
    discovered = {(f.file, f.vulnerability_type) for f in findings}

    for chain in EXPLOIT_CHAINS:
        if all(step in discovered for step in chain):
            return 0.05

    return 0.0

class Grader3(BaseGrader):
    """Reasoning-based grader with multi-axis rubric."""

    def grade(
        self,
        findings: list[Finding],
        ground_truth: list[dict],
        notes: list[str] | None = None,
    ) -> float:

        if not ground_truth:
            return 0.0
        if not findings:
            return 0.0

        entry_scores = []
        used_findings: set[int] = set()

        for gt in ground_truth:
            best_score = 0.0
            best_idx = -1

            for idx, finding in enumerate(findings):
                if idx in used_findings:
                    continue

                type_ok = (
                    _types_match(finding.vulnerability_type, gt["type"])
                    or _semantic_match(finding.vulnerability_type, gt["type"])
                )
                if not type_ok:
                    continue
                if finding.file != gt["file"]:
                    continue

                score = 0.45

                if abs(finding.line_number - gt["line"]) <= LINE_TOLERANCE:
                    score += 0.10

                gt_sev = gt.get("severity", "").lower()
                finding_sev = finding.severity.lower() if finding.severity else ""
                if gt_sev and finding_sev == gt_sev:
                    score += 0.15

                fix_lower = (finding.suggested_fix or "").lower()
                specific = sum(1 for t in SPECIFIC_FIX_TERMS if t in fix_lower)
                if specific >= 2:
                    score += 0.20
                elif specific >= 1:
                    score += 0.10

                if _has_fix_quality(finding.suggested_fix):
                    score += 0.15

                if score > best_score:
                    best_score = score
                    best_idx = idx

            if best_idx >= 0:
                used_findings.add(best_idx)

            entry_scores.append(best_score)

        coverage = sum(entry_scores) / len(ground_truth)

        #False positive penalty
        fp_count = 0
        for finding in findings:
            matched = False
            for gt in ground_truth:
                type_ok = (
                    _types_match(finding.vulnerability_type, gt["type"])
                    or _semantic_match(finding.vulnerability_type, gt["type"])
                )
                if type_ok and finding.file == gt["file"]:
                    matched = True
                    break
            if not matched:
                fp_count += 1

        fp_penalty = fp_count * 0.12

        # Notes bonus
        notes_bonus = 0.0
        if notes:
            combined = " ".join(notes).lower()
            if any(t in combined for t in CHAIN_TERMS):
                notes_bonus = 0.05
            elif len(combined) > 50:
                notes_bonus = 0.02

        # New bonuses
        triage_bonus = _triage_bonus(findings)
        chain_bonus = _chain_bonus(findings)

        raw = coverage - fp_penalty + notes_bonus + triage_bonus + chain_bonus

        return max(0.0, min(1.0, raw))