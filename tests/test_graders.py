"""
Tests for all 3 graders.
Each grader is tested with 5 scenarios: perfect, empty, all false positives,
half correct, and correct type but wrong line.
"""

import pytest

from environment.models import Finding
from environment.graders.grader1 import Grader1
from environment.graders.grader2 import Grader2
from environment.graders.grader3 import Grader3

EPS = 0.01  # Must match environment.reward.STRICT_SCORE_EPS


# ─── Shared fixtures ──────────────────────────────────────────

SAMPLE_GT = [
    {"line": 10, "type": "SQL Injection", "severity": "Critical", "file": "app.py",
     "fix": "Use parameterized queries"},
    {"line": 25, "type": "Hardcoded Secret", "severity": "High", "file": "app.py",
     "fix": "Use environment variables"},
    {"line": 50, "type": "Command Injection", "severity": "Critical", "file": "utils.py",
     "fix": "Use ast.literal_eval()"},
]


def make_finding(
    file="app.py", line=10, vuln_type="SQL Injection",
    severity="Critical", desc="Detailed vulnerability description for testing",
    fix="Use parameterized queries to sanitize input properly"
) -> Finding:
    return Finding(
        file=file, line_number=line, vulnerability_type=vuln_type,
        severity=severity, description=desc, suggested_fix=fix,
    )


def perfect_findings() -> list[Finding]:
    """All GT entries found with correct lines and good fixes."""
    return [
        make_finding(file="app.py", line=10, vuln_type="SQL Injection",
                     severity="Critical", fix="Use parameterized queries to prevent SQL injection"),
        make_finding(file="app.py", line=25, vuln_type="Hardcoded Secret",
                     severity="High", fix="Use os.environ.get() to read from environment variables"),
        make_finding(file="utils.py", line=50, vuln_type="Command Injection",
                     severity="Critical", fix="Replace eval with ast.literal_eval for safe parsing"),
    ]


def half_findings() -> list[Finding]:
    """Only first GT entry found."""
    return [
        make_finding(file="app.py", line=10, vuln_type="SQL Injection",
                     severity="Critical", fix="Use parameterized queries to prevent SQL injection"),
    ]


def false_positive_findings() -> list[Finding]:
    """All wrong types/files — none match GT."""
    return [
        make_finding(file="wrong.py", line=5, vuln_type="SSRF",
                     severity="High", fix="Validate server side request URLs and block internal ranges"),
        make_finding(file="bad.py", line=15, vuln_type="XXE Injection",
                     severity="Critical", fix="Use defusedxml to prevent XML external entity attacks"),
    ]


def wrong_line_findings() -> list[Finding]:
    """Correct type+file but line off by more than allowed."""
    return [
        make_finding(file="app.py", line=20, vuln_type="SQL Injection",
                     severity="Critical", fix="Use parameterized queries to prevent SQL injection"),
        make_finding(file="app.py", line=35, vuln_type="Hardcoded Secret",
                     severity="High", fix="Use os.environ.get() to read from environment variables"),
        make_finding(file="utils.py", line=60, vuln_type="Command Injection",
                     severity="Critical", fix="Replace eval with ast.literal_eval for safe parsing"),
    ]


# ─── Grader 1 Tests ──────────────────────────────────────────

class TestGrader1:
    grader = Grader1()

    def test_perfect_findings(self):
        score = self.grader.grade(perfect_findings(), SAMPLE_GT)
        assert score >= 0.95

    def test_empty_findings(self):
        score = self.grader.grade([], SAMPLE_GT)
        assert score == EPS

    def test_all_false_positives(self):
        score = self.grader.grade(false_positive_findings(), SAMPLE_GT)
        assert score == EPS

    def test_half_correct(self):
        score = self.grader.grade(half_findings(), SAMPLE_GT)
        assert 0.2 <= score <= 0.6

    def test_correct_type_wrong_line(self):
        # Grader1: line proximity adds a bonus on top of the base detection score.
        # When all type+file matches are found, base score is already 1.0
        # (clamped), so wrong-line and perfect both return 1.0 for Grader1.
        # The key behavior: score > 0 (not treated as false positives).
        score = self.grader.grade(wrong_line_findings(), SAMPLE_GT)
        assert score > 0  # type+file match gives positive score regardless of line
        assert score >= 1.0 - EPS  # all 3 GT entries found, clamped to 0.99


# ─── Grader 2 Tests ──────────────────────────────────────────

class TestGrader2:
    grader = Grader2()

    def test_perfect_findings(self):
        score = self.grader.grade(perfect_findings(), SAMPLE_GT)
        assert score >= 0.95

    def test_empty_findings(self):
        score = self.grader.grade([], SAMPLE_GT)
        assert score == EPS

    def test_all_false_positives(self):
        score = self.grader.grade(false_positive_findings(), SAMPLE_GT)
        assert score == EPS

    def test_half_correct(self):
        score = self.grader.grade(half_findings(), SAMPLE_GT)
        assert 0.2 <= score <= 0.6

    def test_correct_type_wrong_line(self):
        score = self.grader.grade(wrong_line_findings(), SAMPLE_GT)
        assert score > 0
        # Should be less than perfect (missing line bonus)
        perfect_score = self.grader.grade(perfect_findings(), SAMPLE_GT)
        assert score <= perfect_score


# ─── Grader 3 Tests ──────────────────────────────────────────

class TestGrader3:
    grader = Grader3()

    def test_perfect_findings(self):
        score = self.grader.grade(perfect_findings(), SAMPLE_GT)
        assert score >= 0.85  # may be slightly less than 1.0 due to weighting

    def test_empty_findings(self):
        score = self.grader.grade([], SAMPLE_GT)
        assert score == EPS

    def test_all_false_positives(self):
        score = self.grader.grade(false_positive_findings(), SAMPLE_GT)
        assert score == EPS

    def test_half_correct(self):
        score = self.grader.grade(half_findings(), SAMPLE_GT)
        assert 0.1 <= score <= 0.6

    def test_correct_type_wrong_line(self):
        score = self.grader.grade(wrong_line_findings(), SAMPLE_GT)
        assert score > 0
