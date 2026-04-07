"""
Regression test: scores must always be strictly in the open interval (0, 1).

The OpenEnv evaluator rejects task scores that are exactly 0.0 or 1.0.
Every public scoring function and every protocol formatting function must
guarantee that the *formatted text* never reads "0.00" or "1.00".

This file is the safety net — if any of these tests fail, the submission
WILL be rejected by Phase 2 validation.
"""

import pytest

from environment.reward import (
    _clamp_open_01,
    STRICT_SCORE_EPS,
    compute_episode_score,
    compute_step_reward,
    compute_triage_score,
)
from environment.graders.grader1 import Grader1
from environment.graders.grader2 import Grader2
from environment.graders.grader3 import Grader3
from environment.models import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(file="app.py", line=10, vuln="SQL Injection", sev="Critical"):
    return Finding(
        file=file,
        line_number=line,
        vulnerability_type=vuln,
        severity=sev,
        description="Detailed vulnerability description for open interval testing",
        suggested_fix="Use parameterized queries to prevent SQL injection attacks",
    )


SAMPLE_GT = [
    {"line": 10, "type": "SQL Injection", "severity": "Critical", "file": "app.py",
     "fix": "Use parameterized queries"},
    {"line": 25, "type": "Hardcoded Secret", "severity": "High", "file": "app.py",
     "fix": "Use environment variables"},
    {"line": 50, "type": "Command Injection", "severity": "Critical", "file": "utils.py",
     "fix": "Use ast.literal_eval()"},
]


def _assert_strictly_open(score: float, label: str = ""):
    """Assert score is in (0, 1) — NOT 0.0, NOT 1.0."""
    assert score > 0.0, f"{label}: score must be > 0.0, got {score}"
    assert score < 1.0, f"{label}: score must be < 1.0, got {score}"


def _assert_formatted_open(score: float, label: str = ""):
    """Assert that when formatted to .2f the text is NOT '0.00' or '1.00'."""
    text = f"{score:.2f}"
    assert text != "0.00", f"{label}: formatted score must not be '0.00', raw={score}"
    assert text != "1.00", f"{label}: formatted score must not be '1.00', raw={score}"


# ---------------------------------------------------------------------------
# 1. _clamp_open_01 must never produce boundary values
# ---------------------------------------------------------------------------

class TestClampOpen01:
    @pytest.mark.parametrize("raw", [
        -100.0, -1.0, -0.5, -0.01, 0.0, 1e-9, 1e-6, 0.001,
        0.5,
        0.999, 0.9999, 0.99999, 1.0, 1.0001, 1.5, 100.0,
    ])
    def test_never_boundary(self, raw):
        clamped = _clamp_open_01(raw)
        _assert_strictly_open(clamped, f"_clamp_open_01({raw})")
        _assert_formatted_open(clamped, f"_clamp_open_01({raw})")

    def test_eps_matches_constant(self):
        """STRICT_SCORE_EPS must be >= 0.01 so .2f formatting is safe."""
        assert STRICT_SCORE_EPS >= 0.01


# ---------------------------------------------------------------------------
# 2. compute_episode_score must always be in (0, 1) — even edge cases
# ---------------------------------------------------------------------------

class TestEpisodeScoreOpenInterval:
    def test_empty_findings(self):
        score = compute_episode_score([], SAMPLE_GT, task_id=1)
        _assert_strictly_open(score, "empty findings")
        _assert_formatted_open(score, "empty findings")

    def test_empty_ground_truth(self):
        score = compute_episode_score([], [], task_id=1)
        _assert_strictly_open(score, "empty GT")
        _assert_formatted_open(score, "empty GT")

    def test_perfect_findings(self):
        findings = [
            _make_finding("app.py", 10, "SQL Injection", "Critical"),
            _make_finding("app.py", 25, "Hardcoded Secret", "High"),
            _make_finding("utils.py", 50, "Command Injection", "Critical"),
        ]
        score = compute_episode_score(findings, SAMPLE_GT, task_id=1)
        _assert_strictly_open(score, "perfect")
        _assert_formatted_open(score, "perfect")


# ---------------------------------------------------------------------------
# 3. All graders must return scores in (0, 1)
# ---------------------------------------------------------------------------

class TestGradersOpenInterval:
    graders = [Grader1(), Grader2(), Grader3()]

    @pytest.mark.parametrize("findings", [
        [],  # empty
        [_make_finding("wrong.py", 99, "SSRF", "High")],  # all FP
    ])
    def test_floor_cases(self, findings):
        for g in self.graders:
            name = type(g).__name__
            if isinstance(g, Grader3):
                score = g.grade(findings, SAMPLE_GT, notes=None)
            else:
                score = g.grade(findings, SAMPLE_GT)
            _assert_strictly_open(score, f"{name} floor")
            _assert_formatted_open(score, f"{name} floor")

    def test_ceiling_cases(self):
        perfect = [
            _make_finding("app.py", 10, "SQL Injection", "Critical"),
            _make_finding("app.py", 25, "Hardcoded Secret", "High"),
            _make_finding("utils.py", 50, "Command Injection", "Critical"),
        ]
        for g in self.graders:
            name = type(g).__name__
            if isinstance(g, Grader3):
                score = g.grade(perfect, SAMPLE_GT, notes=["chain analysis complete"])
            else:
                score = g.grade(perfect, SAMPLE_GT)
            _assert_strictly_open(score, f"{name} ceiling")
            _assert_formatted_open(score, f"{name} ceiling")


# ---------------------------------------------------------------------------
# 4. Protocol formatting smoke test
# ---------------------------------------------------------------------------

class TestProtocolFormattingOpenInterval:
    """Simulate what inference.py does: clamp then format to .2f."""

    @pytest.mark.parametrize("raw_reward", [
        -0.15, -0.10, -0.05, 0.0, 0.01, 0.1, 0.3, 0.5, 0.6, 1.0,
    ])
    def test_protocol_reward_format(self, raw_reward):
        # Replicate inference.py logic
        eps = 0.01
        clamped = max(eps, min(1.0 - eps, float(raw_reward)))
        text = f"{max(0.01, min(0.99, clamped)):.2f}"
        assert text != "0.00", f"raw={raw_reward} formatted to '0.00'"
        assert text != "1.00", f"raw={raw_reward} formatted to '1.00'"


# ---------------------------------------------------------------------------
# 5. compute_triage_score boundary check
# ---------------------------------------------------------------------------

class TestTriageScoreOpenInterval:
    def test_zero_triage(self):
        score, _ = compute_triage_score([], SAMPLE_GT, steps_used=0, max_steps=10)
        # triage returns 0.0 for zero steps, but this is internal-only (not a task score).
        # Just make sure it doesn't crash.
        assert isinstance(score, float)
