"""
Tests for evidence-backed reporting feature flag behavior.
"""

import pytest

import environment.env as env_module
from environment.env import SecurityScannerEnv
from environment.models import Action, ActionType


@pytest.fixture
def env():
    return SecurityScannerEnv()


def test_old_payload_works_when_evidence_mode_off(monkeypatch, env):
    monkeypatch.setattr(env_module, "ENABLE_EVIDENCE_MODE", False)
    env.reset(1)
    result = env.step(Action(
        action_type=ActionType.REPORT_VULNERABILITY,
        payload={
            "file": "vulnerable_code.py",
            "line_number": 9,
            "vulnerability_type": "Hardcoded Secret",
            "severity": "High",
            "description": "API key is hardcoded directly in source code module scope.",
            "suggested_fix": "Move API key to environment variables and load via os.environ.get().",
        },
    ))
    assert result.reward > 0


def test_evidence_mode_rejects_missing_fields(monkeypatch, env):
    monkeypatch.setattr(env_module, "ENABLE_EVIDENCE_MODE", True)
    env.reset(1)
    with pytest.raises(ValueError, match="Evidence mode requires"):
        env.step(Action(
            action_type=ActionType.REPORT_VULNERABILITY,
            payload={
                "file": "vulnerable_code.py",
                "line_number": 9,
                "vulnerability_type": "Hardcoded Secret",
                "severity": "High",
                "description": "API key is hardcoded directly in source code module scope.",
                "suggested_fix": "Move API key to environment variables and load via os.environ.get().",
            },
        ))


def test_evidence_mode_rejects_placeholder_values(monkeypatch, env):
    monkeypatch.setattr(env_module, "ENABLE_EVIDENCE_MODE", True)
    env.reset(1)
    with pytest.raises(ValueError):
        env.step(Action(
            action_type=ActionType.REPORT_VULNERABILITY,
            payload={
                "file": "vulnerable_code.py",
                "line_number": 9,
                "vulnerability_type": "Hardcoded Secret",
                "severity": "High",
                "description": "API key is hardcoded directly in source code module scope.",
                "suggested_fix": "Move API key to environment variables and load via os.environ.get().",
                "function": "load_configuration",
                "data_flow_source": "unknown",
                "sink": "headers['Authorization']",
                "exploitability_reason": "Attacker can reuse leaked bearer token for privileged API access.",
            },
        ))


def test_evidence_mode_accepts_valid_evidence(monkeypatch, env):
    monkeypatch.setattr(env_module, "ENABLE_EVIDENCE_MODE", True)
    env.reset(1)
    result = env.step(Action(
        action_type=ActionType.REPORT_VULNERABILITY,
        payload={
            "file": "vulnerable_code.py",
            "line_number": 9,
            "vulnerability_type": "Hardcoded Secret",
            "severity": "High",
            "description": "API key is hardcoded directly in source code module scope.",
            "suggested_fix": "Move API key to environment variables and load via os.environ.get().",
            "function": "get_api_headers authorization builder",
            "data_flow_source": "module constant API_KEY loaded at import time",
            "sink": "Authorization header in outbound API request",
            "exploitability_reason": "Leaked static token allows replay in downstream privileged API calls.",
        },
    ))
    assert result.reward > 0
