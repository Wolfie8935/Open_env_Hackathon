"""
Tests for precision-aware episode scoring.
"""

from environment.models import Finding
from environment.reward import compute_episode_score


GT = [
    {"line": 9, "type": "Hardcoded Secret", "severity": "High", "file": "vulnerable_code.py"},
    {"line": 65, "type": "SQL Injection", "severity": "Critical", "file": "vulnerable_code.py"},
]


def _tp() -> Finding:
    return Finding(
        file="vulnerable_code.py",
        line_number=9,
        vulnerability_type="Hardcoded Secret",
        severity="High",
        description="Static API key embedded in source and reachable by repository readers.",
        suggested_fix="Move secret to environment variable and rotate leaked key material.",
    )


def _fp() -> Finding:
    return Finding(
        file="vulnerable_code.py",
        line_number=151,
        vulnerability_type="Weak Cryptography",
        severity="High",
        description="Safe helper hashing was incorrectly reported as cryptographic weakness.",
        suggested_fix="Use password hashing algorithm, though this report should not be raised.",
    )


def test_precision_mode_penalizes_spam_relative_to_precise():
    precise = [_tp()]
    spammy = [_tp(), _fp(), _fp()]

    precise_score = compute_episode_score(
        precise, GT, task_id=1, use_precision_scoring=True
    )
    spammy_score = compute_episode_score(
        spammy, GT, task_id=1, use_precision_scoring=True
    )
    assert precise_score > spammy_score


def test_off_mode_matches_previous_behavior_shape():
    precise_off = compute_episode_score(
        [_tp()], GT, task_id=1, use_precision_scoring=False
    )
    spammy_off = compute_episode_score(
        [_tp(), _fp()], GT, task_id=1, use_precision_scoring=False
    )
    # Off mode keeps historical behavior where episode score ignores negative carryover.
    assert precise_off == spammy_off
