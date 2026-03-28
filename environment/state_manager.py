"""
State Manager
Holds all mutable episode state. Only env.py should call into this.
"""

from typing import Optional

from environment.models import Finding, EpisodeState


class StateManager:
    """Manages mutable state for a single episode."""

    def __init__(self):
        self.task = None
        self.step_number: int = 0
        self.findings: list[Finding] = []
        self.notes: list[str] = []
        self.visible_files: set[str] = set()
        self.is_complete: bool = False
        self.cumulative_reward: float = 0.0

    def initialize(self, task) -> None:
        """Reset all state for a new episode with the given task."""
        self.task = task
        self.step_number = 0
        self.findings = []
        self.notes = []
        self.visible_files = set(task.get_initial_files().keys())
        self.is_complete = False
        self.cumulative_reward = 0.0

    def add_finding(self, finding: Finding) -> None:
        """Record a new vulnerability finding."""
        self.findings.append(finding)

    def add_note(self, note: str) -> None:
        """Record an analysis note."""
        self.notes.append(note)

    def reveal_file(self, filename: str) -> bool:
        """Make a hidden file visible to the agent.

        Returns True if the file was newly revealed, False if already
        visible or not found in the task.
        """
        if self.task is None:
            return False

        if filename in self.visible_files:
            return False

        if filename in self.task.files:
            self.visible_files.add(filename)
            return True

        return False

    def increment_step(self) -> None:
        """Advance the step counter. Ends episode if max_steps reached."""
        self.step_number += 1
        if self.task and self.step_number >= self.task.max_steps:
            self.is_complete = True

    def get_visible_file_contents(self) -> dict[str, str]:
        """Return contents of all currently visible files."""
        if self.task is None:
            return {}
        return {
            fname: self.task.files[fname]
            for fname in self.visible_files
            if fname in self.task.files
        }

    def get_available_files(self) -> list[str]:
        """Return list of all files that can be requested."""
        if self.task is None:
            return []
        return [f for f in self.task.files.keys() if f not in self.visible_files]

    def to_state_dict(self) -> dict:
        """Return full episode state as a dictionary."""
        return EpisodeState(
            task_id=self.task.task_id if self.task else 0,
            step_number=self.step_number,
            max_steps=self.task.max_steps if self.task else 0,
            findings=self.findings,
            notes=self.notes,
            visible_files=sorted(self.visible_files),
            all_files=sorted(self.task.files.keys()) if self.task else [],
            is_complete=self.is_complete,
            cumulative_reward=self.cumulative_reward,
        ).model_dump()
