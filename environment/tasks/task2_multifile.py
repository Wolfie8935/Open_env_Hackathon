"""
Task 2: Multi-File Flask Application
Medium difficulty — 4 files, 5 vulnerabilities, 20 steps.
Triage mode active: agents scored on prioritization quality and step efficiency.
"""

from pathlib import Path

from environment.tasks.base_task import BaseTask

class Task2MultiFile(BaseTask):
    """Multi-file Flask application audit — medium difficulty.

    The agent analyzes a file manager application with 4 Python files.
    Only 2 files are visible initially; the agent must request the others.

    Triage mode: agents must report Critical/High vulnerabilities before Medium.
    Score = weighted_recall × prioritization_quality × step_efficiency.
    The primary chain objective is Full RCE Chain (Path Traversal → Insecure Deserialization).
    """

    task_id = 2
    name = "Multi-File Flask App"
    description = (
        "Audit a Flask-based file manager application with user accounts "
        "and an admin panel. The app has 4 source files with 5 security "
        "vulnerabilities. Some files are hidden — use request_file to reveal them. "
        "Triage mode active: report Critical findings before High before Medium."
    )
    difficulty = "medium"
    max_steps = 20

    #Triage Mode
    #Scoring rewards Critical-first prioritization and step efficiency.
    #triage_max_steps is the tight budget within which full efficiency is earned.
    triage_mode: bool = True
    triage_max_steps: int = 12  

    def __init__(self):
        data_dir = Path(__file__).parent.parent / "data" / "task2"
        assert (data_dir / "config.py").exists(), f"Task2 config not found at {data_dir}"

        self.files = self.load_file_contents(data_dir)

        config_content = self.files.get("config.py", "")
        assert "JWT_SECRET" not in config_content, "Wrong config.py loaded for Task2 — found JWT_SECRET"

        from environment.data.task2 import TASK2_GROUND_TRUTH
        self.ground_truth = TASK2_GROUND_TRUTH

    def get_initial_files(self) -> dict[str, str]:
        """Show only app.py and config.py at start.

        Agent must request models.py and utils.py to find all vulnerabilities.
        """
        return {k: v for k, v in self.files.items() if k in ["app.py", "config.py"]}