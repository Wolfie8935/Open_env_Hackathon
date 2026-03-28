"""
Task 1: Single File Audit
Easy difficulty — one file, 3 vulnerabilities, 10 steps.
"""

from pathlib import Path

from environment.tasks.base_task import BaseTask


class Task1SingleFile(BaseTask):
    """Single file security audit — beginner difficulty.

    The agent analyzes one Python module (user management backend)
    and must find 3 common vulnerabilities.
    """

    task_id = 1
    name = "Single File Audit"
    description = (
        "Analyze a single Python module (user management backend) for security "
        "vulnerabilities. The file contains a database manager and data processor "
        "with common security issues. Find all 3 vulnerabilities."
    )
    difficulty = "easy"
    max_steps = 10

    def __init__(self):
        data_dir = Path(__file__).parent.parent / "data" / "task1"
        self.files = self.load_file_contents(data_dir)
        from environment.data.task1.vulnerable_code import GROUND_TRUTH
        self.ground_truth = GROUND_TRUTH

    def get_initial_files(self) -> dict[str, str]:
        """Show all files at start (only 1 file)."""
        return dict(self.files)
