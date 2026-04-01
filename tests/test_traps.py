"""
Tests for adversarial false-positive trap behavior.
"""

from environment.env import SecurityScannerEnv
from environment.models import Action, ActionType


def test_reporting_safe_sha256_trap_is_false_positive():
    env = SecurityScannerEnv()
    env.reset(1)
    result = env.step(Action(
        action_type=ActionType.REPORT_VULNERABILITY,
        payload={
            "file": "vulnerable_code.py",
            "line_number": 151,
            "vulnerability_type": "Weak Cryptography",
            "severity": "High",
            "description": "SHA-256 hashing used in helper appears to be insecure cryptography.",
            "suggested_fix": "Replace SHA-256 with stronger password hashing like argon2.",
        },
    ))
    assert result.reward < 0
    assert "false positive" in result.observation.feedback.lower()


def test_reporting_safe_fixed_url_request_is_false_positive():
    env = SecurityScannerEnv()
    env.reset(2)
    result = env.step(Action(
        action_type=ActionType.REPORT_VULNERABILITY,
        payload={
            "file": "app.py",
            "line_number": 133,
            "vulnerability_type": "SSRF",
            "severity": "High",
            "description": "External request call could be abused for server-side request forgery.",
            "suggested_fix": "Validate and sanitize user-provided URLs before request execution.",
        },
    ))
    assert result.reward < 0
    assert "false positive" in result.observation.feedback.lower()
