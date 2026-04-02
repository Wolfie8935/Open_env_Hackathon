import pytest

from environment.env import SecurityScannerEnv
from environment.models import Action, ActionType
from environment.reward import (
    compute_episode_score,
    compute_triage_score,
    compute_severity_coverage,
)


def _assert_caches_match_pure(env: SecurityScannerEnv) -> None:
    sm = env.state_manager
    task = env.active_task
    assert task is not None

    # severity coverage cache must match pure function output
    pure_cov = compute_severity_coverage(sm.findings, task.ground_truth)
    assert sm.severity_coverage_cache == pure_cov

    # triage cache must match pure function when enabled
    if sm.triage_mode and sm.step_number > 0:
        pure_triage, _ = compute_triage_score(
            sm.findings,
            task.ground_truth,
            steps_used=sm.step_number,
            max_steps=sm.triage_max_steps,
        )
        assert sm.triage_score_cache == pure_triage
    else:
        assert sm.triage_score_cache == 0.0

    # episode score cache must match pure function (step-time uses chain_bonus=0.0)
    pure_episode = compute_episode_score(
        sm.findings,
        task.ground_truth,
        task.task_id,
        notes=sm.notes,
        current_step=sm.step_number,
        max_steps=task.max_steps,
        chain_bonus=0.0,
        use_precision_scoring=True,
    )
    cached_episode = sm.compute_episode_score_cached(
        chain_bonus=0.0,
        use_precision_scoring=True,
        current_step=sm.step_number,
        max_steps=task.max_steps,
    )
    assert cached_episode == pytest.approx(pure_episode)


@pytest.mark.parametrize("task_id", [1, 2, 3])
def test_cached_metrics_match_pure_functions(task_id: int) -> None:
    env = SecurityScannerEnv()
    obs = env.reset(task_id)
    _assert_caches_match_pure(env)

    # mix of cheap and expensive actions; caches must track identically
    env.step(Action(action_type=ActionType.ADD_NOTE, payload={"note": "baseline note"}))
    _assert_caches_match_pure(env)

    # request file where available (task 2 has hidden files; task 1/3 request is no-op or already visible)
    if task_id == 2:
        hidden = [f for f in ["models.py", "utils.py"] if f not in obs.files]
        if hidden:
            env.step(Action(action_type=ActionType.REQUEST_FILE, payload={"filename": hidden[0]}))
            _assert_caches_match_pure(env)

    # report one likely true positive for task1 and one false positive for all tasks
    if task_id == 1:
        env.step(Action(
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
        _assert_caches_match_pure(env)

    env.step(Action(
        action_type=ActionType.REPORT_VULNERABILITY,
        payload={
            "file": list(env.active_task.files.keys())[0],
            "line_number": 1,
            "vulnerability_type": "SSRF",
            "severity": "Critical",
            "description": "Intentional false positive for cache regression test",
            "suggested_fix": "N/A - test payload",
        },
    ))
    _assert_caches_match_pure(env)

