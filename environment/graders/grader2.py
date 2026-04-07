"""
Grader 2: Rubric-Based
Per-entry scoring: 0.60 for type+file, +0.20 for line proximity, +0.20 for fix quality.
"""

from environment.graders.base_grader import BaseGrader
from environment.models import Finding
from environment.reward import normalize_vuln_type, _types_match, _has_fix_quality, LINE_TOLERANCE


class Grader2(BaseGrader):
    """Rubric-based grader with granular per-entry scoring.

    Each GT entry can earn up to 1.0 points:
        - type + file match:    0.60
        - line within ±3:       0.20   (Fix 7: now uses shared LINE_TOLERANCE constant)
        - fix text quality:     0.20
    """

    def grade(self, findings: list[Finding], ground_truth: list[dict]) -> float:
        if not ground_truth:
            return 0.0

        entry_scores = []
        used_findings = set()

        for gt in ground_truth:
            best_score = 0.0
            best_idx = -1

            for idx, finding in enumerate(findings):
                if idx in used_findings:
                    continue

                if not _types_match(finding.vulnerability_type, gt["type"]) or finding.file != gt["file"]:
                    continue

                score = 0.60  # base for type + file match

                # Fix 7: uses shared LINE_TOLERANCE constant (±3)
                if abs(finding.line_number - gt["line"]) <= LINE_TOLERANCE:
                    score += 0.20

                if _has_fix_quality(finding.suggested_fix):
                    score += 0.20

                if score > best_score:
                    best_score = score
                    best_idx = idx

            if best_idx >= 0:
                used_findings.add(best_idx)

            entry_scores.append(best_score)

        coverage = sum(entry_scores) / len(ground_truth)

        # Count false positives
        fp_count = 0
        for idx, finding in enumerate(findings):
            matched = False
            for gt in ground_truth:
                if _types_match(finding.vulnerability_type, gt["type"]) and finding.file == gt["file"]:
                    matched = True
                    break
            if not matched:
                fp_count += 1

        fp_penalty = fp_count * 0.1

        return max(0.0, min(1.0, coverage - fp_penalty))