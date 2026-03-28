"""
Task 2: Multi-File Flask Application
Medium difficulty — 4 files, 5 vulnerabilities, 20 steps.
"""

from pathlib import Path

from environment.tasks.base_task import BaseTask


class Task2MultiFile(BaseTask):
    """Multi-file Flask application audit — medium difficulty.

    The agent analyzes a file manager application with 4 Python files.
    Only 2 files are visible initially; the agent must request the others.
    """

    task_id = 2
    name = "Multi-File Flask App"
    description = (
        "Audit a Flask-based file manager application with user accounts "
        "and an admin panel. The app has 4 source files with 5 security "
        "vulnerabilities. Some files are hidden — use request_file to reveal them."
    )
    difficulty = "medium"
    max_steps = 20

    def __init__(self):
        data_dir = Path(__file__).parent.parent / "data" / "task2"
        self.files = self.load_file_contents(data_dir)
        from environment.data.task2 import TASK2_GROUND_TRUTH
        self.ground_truth = TASK2_GROUND_TRUTH

    def get_initial_files(self) -> dict[str, str]:
        """Show only app.py and config.py at start.

        Agent must request models.py and utils.py to find all vulnerabilities.
        """
        return {k: v for k, v in self.files.items() if k in ["app.py", "config.py"]}
