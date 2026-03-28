"""
Task 2: Multi-File Flask Application
Aggregates ground truth from all component files.
"""

from environment.data.task2.config import GROUND_TRUTH as CONFIG_GT
from environment.data.task2.models import GROUND_TRUTH as MODELS_GT
from environment.data.task2.utils import GROUND_TRUTH as UTILS_GT
from environment.data.task2.app import GROUND_TRUTH as APP_GT

TASK2_GROUND_TRUTH = CONFIG_GT + MODELS_GT + UTILS_GT + APP_GT

__all__ = ["TASK2_GROUND_TRUTH"]
