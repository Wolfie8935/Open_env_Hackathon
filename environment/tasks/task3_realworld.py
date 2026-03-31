"""
Task 3: Real-World SaaS Platform API
Hard difficulty — 5 files, 7 vulnerabilities, 40 steps.
All files are visible at reset.
"""

from pathlib import Path

from environment.tasks.base_task import BaseTask


class Task3RealWorld(BaseTask):
    """Real-world SaaS API audit — hard difficulty.

    The agent analyzes a production-style REST API with authentication,
    webhooks, XML parsing, and user management. All files are visible
    at reset; the challenge is analysis depth and report quality.
    Severity scoring is enabled.
    """

    task_id = 3
    name = "Real-World Project Audit"
    description = (
        "Audit a production-style SaaS platform REST API with authentication, "
        "webhooks, and data import features. The project has 5 source files with "
        "7 security vulnerabilities of varying severity. Severity accuracy is "
        "scored in this task. All files are visible from the start."
    )
    difficulty = "hard"
    max_steps = 40
    severity_scoring_enabled = True

    def __init__(self):
        # EXPLICIT path — never relies on relative imports
        data_dir = Path(__file__).parent.parent / "data" / "task3"

        # Verify we loaded the right config
        assert (data_dir / "config.py").exists(), f"Task3 config not found at {data_dir}"
        assert (data_dir / "auth.py").exists(), f"Task3 auth not found at {data_dir}"

        self.files = self.load_file_contents(data_dir)

        # Verify task3-specific content loaded correctly
        config_content = self.files.get("config.py", "")
        assert "JWT_SECRET" in config_content, "Wrong config.py loaded — missing JWT_SECRET"

        from environment.data.task3 import TASK3_GROUND_TRUTH
        self.ground_truth = TASK3_GROUND_TRUTH

    def get_initial_files(self) -> dict[str, str]:
        """Task 3 starts with all files visible to emphasize deep analysis."""
        return self.files.copy()

