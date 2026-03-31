"""
Tests for the SecurityScannerEnv environment.
"""

import pytest
from fastapi import HTTPException

from environment.env import SecurityScannerEnv
from environment.models import Action, ActionType


@pytest.fixture
def env():
    """Fresh environment instance for each test."""
    return SecurityScannerEnv()


class TestReset:
    """Tests for reset() method."""

    def test_reset_task1(self, env):
        obs = env.reset(1)
        assert obs.task_id == 1
        assert obs.step_number == 0
        assert len(obs.files) > 0
        assert obs.remaining_steps == 10

    def test_reset_task2(self, env):
        obs = env.reset(2)
        assert obs.task_id == 2
        assert obs.remaining_steps == 20
        # Task 2 starts with app.py and config.py
        assert "app.py" in obs.files
        assert "config.py" in obs.files

    def test_reset_task3(self, env):
        obs = env.reset(3)
        assert obs.task_id == 3
        assert obs.remaining_steps == 40
        # Task 3 starts with config.py and views.py
        assert "config.py" in obs.files
        assert "views.py" in obs.files

    def test_reset_invalid_task(self, env):
        with pytest.raises(ValueError):
            env.reset(99)

    def test_reset_clears_previous_episode(self, env):
        env.reset(1)
        env.step(Action(action_type=ActionType.ADD_NOTE, payload={"note": "test note here"}))
        obs = env.reset(1)
        assert len(obs.current_findings) == 0
        assert obs.step_number == 0


class TestStepBeforeReset:
    """Test that step() fails without reset()."""

    def test_step_before_reset_raises(self, env):
        with pytest.raises(HTTPException):
            env.step(Action(action_type=ActionType.ADD_NOTE, payload={"note": "test note here"}))


class TestReportVulnerability:
    """Tests for report_vulnerability action."""

    def test_true_positive_gives_positive_reward(self, env):
        env.reset(1)
        result = env.step(Action(
            action_type=ActionType.REPORT_VULNERABILITY,
            payload={
                "file": "vulnerable_code.py",
                "line_number": 9,
                "vulnerability_type": "Hardcoded Secret",
                "severity": "High",
                "description": "API key is hardcoded directly in the source code",
                "suggested_fix": "Use os.environ.get() to read API key from environment variables",
            },
        ))
        assert result.reward > 0
        assert not result.done

    def test_false_positive_gives_negative_reward(self, env):
        env.reset(1)
        result = env.step(Action(
            action_type=ActionType.REPORT_VULNERABILITY,
            payload={
                "file": "vulnerable_code.py",
                "line_number": 1,
                "vulnerability_type": "SSRF",
                "severity": "Critical",
                "description": "This is a totally fake vulnerability that does not exist",
                "suggested_fix": "This is a fake fix suggestion for a nonexistent issue",
            },
        ))
        assert result.reward < 0

    def test_duplicate_finding_gives_penalty(self, env):
        """Duplicate (file + type) reports incur the DUPLICATE_PENALTY of -0.05."""
        env.reset(1)
        payload = {
            "file": "vulnerable_code.py",
            "line_number": 9,
            "vulnerability_type": "Hardcoded Secret",
            "severity": "High",
            "description": "API key is hardcoded directly in the source code",
            "suggested_fix": "Use os.environ.get() to read API key from environment variables",
        }
        # First report — true positive
        r1 = env.step(Action(action_type=ActionType.REPORT_VULNERABILITY, payload=payload))
        assert r1.reward > 0

        # Duplicate report — env applies DUPLICATE_PENALTY (-0.05) per documented behavior
        r2 = env.step(Action(action_type=ActionType.REPORT_VULNERABILITY, payload=payload))
        assert r2.reward == pytest.approx(-0.05)


class TestRequestFile:
    """Tests for request_file action."""

    def test_reveals_hidden_file(self, env):
        obs = env.reset(2)
        # Task 2 hides models.py and utils.py at start
        assert "models.py" not in obs.files

        result = env.step(Action(
            action_type=ActionType.REQUEST_FILE,
            payload={"filename": "models.py"},
        ))
        assert "models.py" in result.observation.files
        assert result.reward == 0.0  # neutral action

    def test_request_nonexistent_file(self, env):
        env.reset(1)
        result = env.step(Action(
            action_type=ActionType.REQUEST_FILE,
            payload={"filename": "nonexistent.py"},
        ))
        assert "not found" in result.observation.feedback.lower()


class TestMarkComplete:
    """Tests for mark_complete action."""

    def test_ends_episode(self, env):
        env.reset(1)
        result = env.step(Action(
            action_type=ActionType.MARK_COMPLETE,
            payload={},
        ))
        assert result.done is True
        assert "complete" in result.observation.feedback.lower()

    def test_episode_score_in_info(self, env):
        env.reset(1)
        # Report one true positive first
        env.step(Action(
            action_type=ActionType.REPORT_VULNERABILITY,
            payload={
                "file": "vulnerable_code.py",
                "line_number": 9,
                "vulnerability_type": "Hardcoded Secret",
                "severity": "High",
                "description": "API key hardcoded in source code at module level",
                "suggested_fix": "Move to os.environ.get() environment variable configuration",
            },
        ))
        result = env.step(Action(
            action_type=ActionType.MARK_COMPLETE,
            payload={},
        ))
        assert "episode_score" in result.info
        assert result.info["episode_score"] > 0


class TestMaxSteps:
    """Test that episode terminates at max_steps."""

    def test_terminates_at_max_steps(self, env):
        env.reset(1)  # max_steps = 10
        for i in range(10):
            result = env.step(Action(
                action_type=ActionType.ADD_NOTE,
                payload={"note": f"Step {i} analysis note for testing purposes"},
            ))
        assert result.done is True


class TestState:
    """Tests for the state() method."""

    def test_state_returns_full_info(self, env):
        env.reset(1)
        state = env.state()
        assert state["task_id"] == 1
        assert state["step_number"] == 0
        assert state["is_complete"] is False
        assert "visible_files" in state
        assert "all_files" in state

    def test_state_before_reset_raises(self, env):
        with pytest.raises(HTTPException):
            env.state()


class TestGroundTruthHidden:
    """Test that ground truth is not exposed to the agent."""

    def test_task1_ground_truth_stripped(self, env):
        obs = env.reset(1)
        for content in obs.files.values():
            assert "GROUND_TRUTH" not in content

    def test_task2_ground_truth_stripped(self, env):
        obs = env.reset(2)
        for content in obs.files.values():
            assert "GROUND_TRUTH" not in content

    def test_task3_ground_truth_stripped(self, env):
        obs = env.reset(3)
        for content in obs.files.values():
            assert "GROUND_TRUTH" not in content
