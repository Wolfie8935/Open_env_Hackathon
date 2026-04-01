"""
Base Grader
Abstract base class for all grading strategies.

This file also provides shared deterministic utilities used by all graders.
"""

from abc import ABC, abstractmethod
from typing import List, Dict

from environment.models import Finding

#Deterministic Finding
def fingerprint_finding(f: Finding) -> tuple:
    """
    Create deterministic key for a finding.
    Used to prevent duplicate scoring and ensure reproducibility.
    """
    return (
        f.file,
        f.line_number,
        f.vulnerability_type.lower().strip(),
    )

#Anti-Shortcut Detection
GENERIC_TERMS = {
    "generic",
    "unknown",
    "possible vulnerability",
    "maybe vulnerable",
}

def is_low_quality_finding(f: Finding) -> bool:
    """
    Detect shortcut / lazy findings that lack real evidence.
    """
    if not f.vulnerability_type:
        return True

    vt = f.vulnerability_type.lower()

    if vt in GENERIC_TERMS:
        return True

    if len(vt) < 4:
        return True

    if f.line_number <= 0:
        return True

    return False

#Severity Priority Utility (Triage Mode)
SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}

def triage_priority_score(findings: List[Finding]) -> float:
    """
    Reward agents that report vulnerabilities in risk priority order.

    Critical → High → Medium → Low
    """

    if not findings:
        return 0.0

    ranks = [
        SEVERITY_RANK.get(f.severity.lower(), 1)
        for f in findings
    ]

    sorted_ranks = sorted(ranks, reverse=True)

    if ranks == sorted_ranks:
        return 0.05

    return 0.0

#Exploit Chain Validation
def exploit_chain_detected(
    findings: List[Finding],
    chain: List[tuple[str, str]]
) -> bool:
    """
    Check if a required exploit chain exists in the findings.

    chain example:
    [
        ("config.py","JWT Misconfiguration"),
        ("auth.py","Timing Attack"),
        ("views.py","IDOR")
    ]
    """

    discovered = {
        (f.file, f.vulnerability_type)
        for f in findings
    }

    for step in chain:
        if step not in discovered:
            return False

    return True

#Precision Utility
def compute_precision(
    findings: List[Finding],
    ground_truth: List[Dict]
) -> float:
    """
    Compute precision of findings.
    """

    if not findings:
        return 0.0

    gt_set = {
        (g["file"], g["type"])
        for g in ground_truth
    }

    tp = 0

    for f in findings:
        if (f.file, f.vulnerability_type) in gt_set:
            tp += 1

    return tp / len(findings)

#Base Interface
class BaseGrader(ABC):
    """Abstract grader interface. All graders return a score in [0.0, 1.0]."""

    @abstractmethod
    def grade(self, findings: list[Finding], ground_truth: list[dict]) -> float:
        """Grade a set of findings against ground truth.

        Args:
            findings: The agent's reported vulnerabilities.
            ground_truth: The expected vulnerabilities.

        Returns:
            A score in [0.0, 1.0]. Pure function — no side effects.
        """