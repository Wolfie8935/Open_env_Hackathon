"""
Base Grader
Abstract base class for all grading strategies.
"""

from abc import ABC, abstractmethod
from environment.models import Finding


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
