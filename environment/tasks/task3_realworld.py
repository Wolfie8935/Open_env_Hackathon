"""
Task 3: Real-World SaaS Platform API
Hard difficulty — 5 files, 7 vulnerabilities, 40 steps.
"""

from pathlib import Path

from environment.tasks.base_task import BaseTask


class Task3RealWorld(BaseTask):
    """Real-world SaaS API audit — hard difficulty.

    The agent analyzes a production-style REST API with authentication,
    webhooks, XML parsing, and user management. Only 2 of 5 files are
    initially visible. Severity scoring is enabled.
    """

    task_id = 3
    name = "Real-World Project Audit"
    description = (
        "Audit a production-style SaaS platform REST API with authentication, "
        "webhooks, and data import features. The project has 5 source files with "
        "7 security vulnerabilities of varying severity. Severity accuracy is "
        "scored in this task. Request hidden files to find all issues."
    )
    difficulty = "hard"
    max_steps = 40
    severity_scoring_enabled = True

    def __init__(self):
        data_dir = Path(__file__).parent.parent / "data" / "task3"
        self.files = self.load_file_contents(data_dir)
        from environment.data.task3 import TASK3_GROUND_TRUTH
        self.ground_truth = TASK3_GROUND_TRUTH

    def get_initial_files(self) -> dict[str, str]:
        """Show only config.py and views.py at start.

        Agent must request auth.py, serializers.py, and middleware.py.
        """
        return {k: v for k, v in self.files.items() if k in ["config.py", "views.py"]}
