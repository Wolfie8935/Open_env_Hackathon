"""
Grader 1: Detection Accuracy
Counts correct type+file matches, adds line bonus, subtracts false positive penalty.
"""

from environment.graders.base_grader import BaseGrader
from environment.models import Finding
from environment.reward import normalize_vuln_type, _types_match


class Grader1(BaseGrader):
    """Detection accuracy grader.

    Score = (correct_count / total_gt) + (line_bonus_weight) - fp_penalty
    """

    def grade(self, findings: list[Finding], ground_truth: list[dict]) -> float:
        if not ground_truth:
            return 0.0

        correct_count = 0
        line_bonus = 0.0
        matched_gt_indices = set()

        for finding in findings:
            for i, gt in enumerate(ground_truth):
                if i in matched_gt_indices:
                    continue
                if _types_match(finding.vulnerability_type, gt["type"]) and finding.file == gt["file"]:
                    correct_count += 1
                    matched_gt_indices.add(i)
                    if abs(finding.line_number - gt["line"]) <= 1:
                        line_bonus += 0.5
                    break

        # Count false positives
        fp_count = 0
        for finding in findings:
            matched = False
            for gt in ground_truth:
                if _types_match(finding.vulnerability_type, gt["type"]) and finding.file == gt["file"]:
                    matched = True
                    break
            if not matched:
                fp_count += 1

        fp_penalty = fp_count * 0.1

        raw = (correct_count / len(ground_truth)) + (
            line_bonus / len(ground_truth) * 0.2
        ) - fp_penalty

        return max(0.0, min(1.0, raw))
