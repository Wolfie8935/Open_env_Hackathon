"""
Task 3: Real-World SaaS Platform API
Hard difficulty — 5 files, 7 vulnerabilities, 40 steps.
Uses TRIAGE mode: initial files shown as skeletons.
"""

import ast
from pathlib import Path

from environment.tasks.base_task import BaseTask


class Task3RealWorld(BaseTask):
    """Real-world SaaS API audit — hard difficulty.

    The agent analyzes a production-style REST API with authentication,
    webhooks, XML parsing, and user management. Only file SKELETONS are
    initially visible. Agent must request_file to see full content.
    Severity scoring is enabled.
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
        """Task 3 starts with file skeletons — only signatures visible.

        Agent must request_file to see full content.
        This forces deliberate file selection based on architecture understanding.
        """
        skeletons = {}
        for fname in ["config.py", "views.py"]:
            if fname in self.files:
                skeletons[fname] = self._get_skeleton(self.files[fname])
        return skeletons

    def _get_skeleton(self, content: str) -> str:
        """Extract only class/function signatures from a file."""
        lines = content.split('\n')
        skeleton_lines = ['# [FILE SKELETON — use request_file to see full content]', '']
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    lineno = node.lineno
                    if lineno <= len(lines):
                        skeleton_lines.append(f"# Line {lineno}: {lines[lineno-1].strip()}")
        except SyntaxError:
            skeleton_lines.append('# [Could not parse — request file for full content]')
        return '\n'.join(skeleton_lines)
