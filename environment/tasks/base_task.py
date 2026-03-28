"""
Base Task
Abstract base class for all security scanner tasks.
"""

import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional

from environment.models import TaskInfo


class BaseTask(ABC):
    """Abstract base class for security scanner tasks.

    Subclasses must define task metadata and implement file visibility.
    """

    task_id: int
    name: str
    description: str
    difficulty: str
    max_steps: int
    files: dict[str, str]
    ground_truth: list[dict]

    @abstractmethod
    def get_initial_files(self) -> dict[str, str]:
        """Return files shown to the agent at episode start."""

    def get_task_info(self) -> TaskInfo:
        """Return task metadata for the /tasks endpoint."""
        vuln_types = list({gt["type"] for gt in self.ground_truth})
        return TaskInfo(
            task_id=self.task_id,
            name=self.name,
            description=self.description,
            difficulty=self.difficulty,
            max_steps=self.max_steps,
            num_vulnerabilities=len(self.ground_truth),
            vulnerability_types=sorted(vuln_types),
        )

    def load_file_contents(self, data_dir: Path) -> dict[str, str]:
        """Read all .py files from a data directory.

        Strips the GROUND_TRUTH block from each file so the agent
        cannot simply read the answers.
        """
        files = {}
        for py_file in sorted(data_dir.glob("*.py")):
            if py_file.name == "__init__.py":
                continue

            content = py_file.read_text(encoding="utf-8")
            cleaned = self._strip_ground_truth(content)
            files[py_file.name] = cleaned

        return files

    def _strip_ground_truth(self, content: str) -> str:
        """Remove the GROUND_TRUTH assignment block from source code.

        Looks for the marker comment '# --- GROUND TRUTH ---' and
        removes everything from that point to the end of the file.
        """
        marker = "# --- GROUND TRUTH ---"
        idx = content.find(marker)
        if idx != -1:
            cleaned = content[:idx].rstrip()
            return cleaned

        # Fallback: try regex to remove GROUND_TRUTH = [...] block
        pattern = r"\nGROUND_TRUTH\s*=\s*\[.*$"
        cleaned = re.sub(pattern, "", content, flags=re.DOTALL)
        return cleaned.rstrip()
