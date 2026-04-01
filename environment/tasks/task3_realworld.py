"""
Task 3: Real-World SaaS Platform API
Hard difficulty — 5 files, 7 vulnerabilities, 40 steps.
All files are listed at reset, but start as lightweight previews.
Agents must request files to reveal full content.

This task also includes:
- Exploit-chain reasoning objective
- Risk-prioritized triage mode
"""

from pathlib import Path

from environment.tasks.base_task import BaseTask

class Task3RealWorld(BaseTask):
    """Real-world SaaS API audit — hard difficulty.

    The agent analyzes a production-style REST API with authentication,
    webhooks, XML parsing, and user management.

    Additional evaluation goals:
        • Exploit-chain reasoning
        • Risk-prioritized vulnerability triage
        • Accurate severity classification
        • Methodology documentation
    """

    task_id = 3
    name = "Real-World Project Audit"

    description = (
        "Audit a production-style SaaS platform REST API with authentication, "
        "webhooks, and data import features. The project has 5 source files with "
        "7 security vulnerabilities of varying severity. Severity accuracy is "
        "scored in this task.\n\n"

        "Additional Objectives:\n"
        "1. Identify the account takeover exploit chain:\n"
        "   JWT Misconfiguration → Timing Attack → IDOR.\n"
        "2. Prioritize vulnerabilities by risk severity.\n"
        "3. Provide actionable security fixes and reasoning."
    )

    difficulty = "hard"
    max_steps = 40
    severity_scoring_enabled = True

    #New Evaluation Metadata 
    exploit_chain_objective = [
        ("config.py", "JWT Misconfiguration"),
        ("auth.py", "Timing Attack"),
        ("views.py", "IDOR"),
    ]

    triage_mode = True
    triage_top_n = 3
    triage_step_budget = 20

    expected_attack_chain_name = "Complete Account Takeover"

    def __init__(self):

        #EXPLICIT path — never relies on relative imports
        data_dir = Path(__file__).parent.parent / "data" / "task3"

        #Verify we loaded the right config
        assert (data_dir / "config.py").exists(), f"Task3 config not found at {data_dir}"
        assert (data_dir / "auth.py").exists(), f"Task3 auth not found at {data_dir}"

        self.files = self.load_file_contents(data_dir)

        #Verify task3-specific content loaded correctly
        config_content = self.files.get("config.py", "")
        assert "JWT_SECRET" in config_content, "Wrong config.py loaded — missing JWT_SECRET"

        from environment.data.task3 import TASK3_GROUND_TRUTH
        self.ground_truth = TASK3_GROUND_TRUTH

    def get_initial_files(self) -> dict[str, str]:
        """Task 3 starts with previews; request_file reveals full source."""
        previews: dict[str, str] = {}
        preview_lines = 18

        for filename, content in self.files.items():
            lines = content.splitlines()
            head = "\n".join(lines[:preview_lines])
            omitted = max(0, len(lines) - preview_lines)
            previews[filename] = (
                f"# PREVIEW ONLY: request_file('{filename}') to reveal full source\n"
                f"# Preview lines shown: 1..{min(preview_lines, len(lines))}\n"
                f"# Omitted lines: {omitted}\n\n"
                f"{head}"
            )

        return previews