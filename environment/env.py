"""
Security Scanner Environment
The main environment class implementing the OpenEnv contract.
"""

from fastapi import HTTPException

from environment.models import (
    Action,
    ActionType,
    Finding,
    Observation,
    StepResult,
)
from environment.reward import compute_episode_score, compute_step_reward
from environment.state_manager import StateManager


class SecurityScannerEnv:
    """OpenEnv-compatible security vulnerability scanner environment.

    Supports 3 tasks of increasing difficulty. The agent interacts via
    reset() and step() to find vulnerabilities in Python codebases.
    """

    def __init__(self):
        self.state_manager = StateManager()
        self.active_task = None
        self._initialized = False

    def reset(self, task_id: int) -> Observation:
        """Start a new episode for the given task.

        Args:
            task_id: 1, 2, or 3

        Returns:
            Initial Observation with visible files and task context.
        """
        task = self._load_task(task_id)
        self.active_task = task
        self.state_manager.initialize(task)
        self._initialized = True

        return Observation(
            files=self.state_manager.get_visible_file_contents(),
            current_findings=[],
            step_number=0,
            task_id=task_id,
            feedback=(
                f"Episode started for Task {task_id}: {task.name}. "
                f"Analyze the code and report security vulnerabilities. "
                f"You have {task.max_steps} steps. "
                f"Files visible: {sorted(self.state_manager.visible_files)}. "
                f"Hidden files available to request: {self.state_manager.get_available_files()}"
            ),
            remaining_steps=task.max_steps,
        )

    def step(self, action: Action) -> StepResult:
        """Process an agent action and return the result.

        Args:
            action: The agent's chosen action.

        Returns:
            StepResult with observation, reward, done flag, and info.

        Raises:
            HTTPException: 409 if called before reset().
        """
        if not self._initialized:
            raise HTTPException(status_code=409, detail="Call /reset first")

        if self.state_manager.is_complete:
            return self._terminal_result("Episode already complete.")

        reward = 0.0
        feedback = ""
        breakdown = {}

        if action.action_type == ActionType.REPORT_VULNERABILITY:
            reward, feedback, breakdown = self._handle_report(action.payload)

        elif action.action_type == ActionType.REQUEST_FILE:
            feedback = self._handle_request_file(action.payload)

        elif action.action_type == ActionType.MARK_COMPLETE:
            feedback, episode_score = self._handle_mark_complete()
            breakdown["episode_score"] = episode_score

        elif action.action_type == ActionType.ADD_NOTE:
            feedback = self._handle_add_note(action.payload)

        self.state_manager.cumulative_reward += reward
        self.state_manager.increment_step()

        observation = Observation(
            files=self.state_manager.get_visible_file_contents(),
            current_findings=self.state_manager.findings,
            step_number=self.state_manager.step_number,
            task_id=self.active_task.task_id,
            feedback=feedback,
            remaining_steps=max(
                0, self.active_task.max_steps - self.state_manager.step_number
            ),
        )

        episode_score = compute_episode_score(
            self.state_manager.findings,
            self.active_task.ground_truth,
            self.active_task.task_id,
            notes=self.state_manager.notes,
        )

        # Clamp reward to spec range [-0.5, 0.6]
        clamped_reward = max(-0.5, min(0.6, reward))

        return StepResult(
            observation=observation,
            reward=clamped_reward,
            done=self.state_manager.is_complete,
            info={
                "episode_score": episode_score,
                "step_reward_breakdown": breakdown,
                "grader_feedback": feedback,
                "cumulative_reward": self.state_manager.cumulative_reward,
                "findings_count": len(self.state_manager.findings),
                "ground_truth_count": len(self.active_task.ground_truth),
            },
        )

    def state(self) -> dict:
        """Return the full episode state."""
        if not self._initialized:
            raise HTTPException(status_code=409, detail="No active episode. Call /reset first")
        return self.state_manager.to_state_dict()

    def _handle_report(self, payload: dict) -> tuple[float, str, dict]:
        """Process a vulnerability report action."""
        try:
            finding = Finding(
                file=payload["file"],
                line_number=payload["line_number"],
                vulnerability_type=payload["vulnerability_type"],
                severity=payload["severity"],
                description=payload["description"],
                suggested_fix=payload["suggested_fix"],
            )
        except (KeyError, ValueError) as e:
            return 0.0, f"Invalid finding payload: {e}", {}

        reward, breakdown = compute_step_reward(
            finding,
            self.active_task.ground_truth,
            self.active_task.task_id,
            self.state_manager.findings,
        )

        self.state_manager.add_finding(finding)

        if reward > 0:
            feedback = (
                f"Finding recorded: {finding.vulnerability_type} in {finding.file} "
                f"at line {finding.line_number}. Reward: {reward:+.2f}"
            )
        elif reward < 0:
            feedback = (
                f"False positive recorded: {finding.vulnerability_type} in "
                f"{finding.file}. Penalty: {reward:+.2f}"
            )
        else:
            feedback = (
                f"Duplicate or zero-reward finding: {finding.vulnerability_type} "
                f"in {finding.file}."
            )

        return reward, feedback, breakdown

    def _handle_request_file(self, payload: dict) -> str:
        """Process a file request action."""
        filename = payload.get("filename", "")
        if self.state_manager.reveal_file(filename):
            available = self.state_manager.get_available_files()
            return (
                f"File '{filename}' is now visible. "
                f"Remaining hidden files: {available if available else 'none'}"
            )
        elif filename in self.state_manager.visible_files:
            return f"File '{filename}' is already visible."
        else:
            all_files = sorted(self.active_task.files.keys())
            return f"File '{filename}' not found in this task. Available files: {all_files}"

    def _handle_mark_complete(self) -> tuple[str, float]:
        """Process a mark-complete action."""
        self.state_manager.is_complete = True
        episode_score = compute_episode_score(
            self.state_manager.findings,
            self.active_task.ground_truth,
            self.active_task.task_id,
            notes=self.state_manager.notes,
        )
        found = len(self.state_manager.findings)
        total = len(self.active_task.ground_truth)
        return (
            f"Episode complete. Findings: {found}, "
            f"Ground truth total: {total}, "
            f"Final score: {episode_score:.3f}"
        ), episode_score

    def _handle_add_note(self, payload: dict) -> str:
        """Process an add-note action."""
        note = payload.get("note", "")
        if note:
            self.state_manager.add_note(note)
            return f"Note recorded: {note[:80]}{'...' if len(note) > 80 else ''}"
        return "Empty note ignored."

    def _terminal_result(self, feedback: str) -> StepResult:
        """Build a terminal StepResult when the episode is already done."""
        episode_score = compute_episode_score(
            self.state_manager.findings,
            self.active_task.ground_truth,
            self.active_task.task_id,
            notes=self.state_manager.notes,
        )
        return StepResult(
            observation=Observation(
                files=self.state_manager.get_visible_file_contents(),
                current_findings=self.state_manager.findings,
                step_number=self.state_manager.step_number,
                task_id=self.active_task.task_id,
                feedback=feedback,
                remaining_steps=0,
            ),
            reward=0.0,
            done=True,
            info={
                "episode_score": episode_score,
                "step_reward_breakdown": {},
                "grader_feedback": feedback,
                "cumulative_reward": self.state_manager.cumulative_reward,
                "findings_count": len(self.state_manager.findings),
                "ground_truth_count": len(self.active_task.ground_truth),
            },
        )

    def _load_task(self, task_id: int):
        """Load a task by ID."""
        if task_id == 1:
            from environment.tasks.task1_single_file import Task1SingleFile
            return Task1SingleFile()
        elif task_id == 2:
            from environment.tasks.task2_multifile import Task2MultiFile
            return Task2MultiFile()
        elif task_id == 3:
            from environment.tasks.task3_realworld import Task3RealWorld
            return Task3RealWorld()
        else:
            raise ValueError(f"Invalid task_id: {task_id}. Must be 1, 2, or 3.")
