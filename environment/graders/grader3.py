"""
Grader 3: Weighted Composite
Three-component score: Detection (50%), Severity Ranking (30%), Fix Quality (20%).
"""

from environment.graders.base_grader import BaseGrader
from environment.models import Finding
from environment.reward import normalize_vuln_type, _types_match, _has_fix_quality


class Grader3(BaseGrader):
    """Weighted composite grader testing full auditor skill set.

    Components:
        - Detection (0.50): fraction of GT entries found
        - Severity Ranking (0.30): severity accuracy for true positives
        - Fix Quality (0.20): meaningful fix suggestions for true positives
    """

    def grade(self, findings: list[Finding], ground_truth: list[dict]) -> float:
        if not ground_truth:
            return 0.0

        # Identify true positives
        true_positives = []
        matched_gt = []
        used_gt_indices = set()

        for finding in findings:
            for i, gt in enumerate(ground_truth):
                if i in used_gt_indices:
                    continue
                if _types_match(finding.vulnerability_type, gt["type"]) and finding.file == gt["file"]:
                    true_positives.append(finding)
                    matched_gt.append(gt)
                    used_gt_indices.add(i)
                    break

        # Component 1 — Detection (weight 0.50)
        detection_score = len(true_positives) / len(ground_truth)

        # Component 2 — Severity Ranking (weight 0.30)
        severity_matches = 0
        for finding, gt in zip(true_positives, matched_gt):
            if finding.severity.lower().strip() == gt["severity"].lower().strip():
                severity_matches += 1
        severity_score = severity_matches / len(ground_truth) if ground_truth else 0.0

        # Component 3 — Fix Quality (weight 0.20)
        quality_fixes = 0
        for finding in true_positives:
            if len(finding.suggested_fix) > 20 and _has_fix_quality(finding.suggested_fix):
                quality_fixes += 1
        fix_score = quality_fixes / max(1, len(true_positives))

        # False positive penalty
        fp_count = len(findings) - len(true_positives)
        fp_penalty = fp_count * 0.1

        final = (
            0.50 * detection_score
            + 0.30 * severity_score
            + 0.20 * fix_score
            - fp_penalty
        )

        return max(0.0, min(1.0, final))
