"""
Tests for Pydantic models and enums.
"""

import pytest
from pydantic import ValidationError

from environment.models import (
    Action,
    ActionType,
    Finding,
    Observation,
    Severity,
    StepResult,
    VulnerabilityType,
)


class TestVulnerabilityType:
    """Tests for VulnerabilityType enum and normalization."""

    def test_all_15_values_exist(self):
        """Verify all 15 vulnerability types are defined."""
        assert len(VulnerabilityType) == 15

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("SQL Injection", VulnerabilityType.SQL_INJECTION),
            ("sql injection", VulnerabilityType.SQL_INJECTION),
            ("SQL_INJECTION", VulnerabilityType.SQL_INJECTION),
            ("Sql Injection", VulnerabilityType.SQL_INJECTION),
            ("sql_injection", VulnerabilityType.SQL_INJECTION),
            ("Hardcoded Secret", VulnerabilityType.HARDCODED_SECRET),
            ("hardcoded secret", VulnerabilityType.HARDCODED_SECRET),
            ("HARDCODED_SECRET", VulnerabilityType.HARDCODED_SECRET),
            ("Command Injection", VulnerabilityType.COMMAND_INJECTION),
            ("Path Traversal", VulnerabilityType.PATH_TRAVERSAL),
            ("directory traversal", VulnerabilityType.PATH_TRAVERSAL),
            ("Insecure Deserialization", VulnerabilityType.INSECURE_DESERIALIZATION),
            ("pickle", VulnerabilityType.INSECURE_DESERIALIZATION),
            ("Broken Authentication", VulnerabilityType.BROKEN_AUTH),
            ("missing auth", VulnerabilityType.BROKEN_AUTH),
            ("Weak Cryptography", VulnerabilityType.WEAK_CRYPTO),
            ("md5", VulnerabilityType.WEAK_CRYPTO),
            ("SSRF", VulnerabilityType.SSRF),
            ("XXE Injection", VulnerabilityType.XXE),
            ("xml external entity", VulnerabilityType.XXE),
            ("IDOR", VulnerabilityType.IDOR),
            ("Mass Assignment", VulnerabilityType.MASS_ASSIGNMENT),
            ("Timing Attack", VulnerabilityType.TIMING_ATTACK),
            ("side channel", VulnerabilityType.TIMING_ATTACK),
            ("CORS Misconfiguration", VulnerabilityType.CORS_MISCONFIGURATION),
            ("Debug Mode", VulnerabilityType.DEBUG_MODE),
            ("JWT Misconfiguration", VulnerabilityType.JWT_MISCONFIGURATION),
        ],
    )
    def test_normalize_matches(self, raw, expected):
        """VulnerabilityType.normalize handles various input formats."""
        assert VulnerabilityType.normalize(raw) == expected

    def test_normalize_returns_none_for_unknown(self):
        """Unknown strings return None."""
        assert VulnerabilityType.normalize("completely_unknown_type") is None


class TestSeverity:
    """Tests for Severity enum."""

    def test_all_4_values(self):
        assert len(Severity) == 4

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Critical", Severity.CRITICAL),
            ("critical", Severity.CRITICAL),
            ("High", Severity.HIGH),
            ("Medium", Severity.MEDIUM),
            ("Low", Severity.LOW),
        ],
    )
    def test_normalize(self, raw, expected):
        assert Severity.normalize(raw) == expected


class TestFinding:
    """Tests for the Finding model."""

    def _make_finding(self, **overrides) -> Finding:
        defaults = {
            "file": "app.py",
            "line_number": 10,
            "vulnerability_type": "SQL Injection",
            "severity": "Critical",
            "description": "This is a detailed vulnerability description for testing purposes",
            "suggested_fix": "Use parameterized queries instead of string formatting",
        }
        defaults.update(overrides)
        return Finding(**defaults)

    def test_valid_finding(self):
        f = self._make_finding()
        assert f.file == "app.py"
        assert f.line_number == 10

    def test_rejects_empty_description(self):
        with pytest.raises(ValidationError):
            self._make_finding(description="short")

    def test_rejects_empty_fix(self):
        with pytest.raises(ValidationError):
            self._make_finding(suggested_fix="fix")

    def test_rejects_negative_line(self):
        with pytest.raises(ValidationError):
            self._make_finding(line_number=0)


class TestAction:
    """Tests for the Action model."""

    def test_valid_report_action(self):
        a = Action(action_type=ActionType.REPORT_VULNERABILITY, payload={"file": "x.py"})
        assert a.action_type == ActionType.REPORT_VULNERABILITY

    def test_valid_mark_complete(self):
        a = Action(action_type=ActionType.MARK_COMPLETE, payload={})
        assert a.action_type == ActionType.MARK_COMPLETE

    def test_invalid_action_type(self):
        with pytest.raises(ValidationError):
            Action(action_type="invalid_type", payload={})


class TestStepResult:
    """Tests for the StepResult model."""

    def test_reward_in_range(self):
        obs = Observation(
            files={}, current_findings=[], step_number=0,
            task_id=1, feedback="test", remaining_steps=10,
        )
        sr = StepResult(observation=obs, reward=0.5, done=False, info={})
        assert sr.reward == 0.5

    def test_reward_rejects_out_of_range(self):
        obs = Observation(
            files={}, current_findings=[], step_number=0,
            task_id=1, feedback="test", remaining_steps=10,
        )
        with pytest.raises(ValidationError):
            StepResult(observation=obs, reward=2.0, done=False, info={})
