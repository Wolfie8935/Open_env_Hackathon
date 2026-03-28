"""
Task 3: Real-World SaaS Platform API
Aggregates ground truth from all component files.
"""

from environment.data.task3.config import GROUND_TRUTH as CONFIG_GT
from environment.data.task3.auth import GROUND_TRUTH as AUTH_GT
from environment.data.task3.views import GROUND_TRUTH as VIEWS_GT
from environment.data.task3.serializers import GROUND_TRUTH as SERIALIZERS_GT
from environment.data.task3.middleware import GROUND_TRUTH as MIDDLEWARE_GT

TASK3_GROUND_TRUTH = CONFIG_GT + AUTH_GT + VIEWS_GT + SERIALIZERS_GT + MIDDLEWARE_GT

# Sort by severity for grader3's severity ranking test
_SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
TASK3_GROUND_TRUTH.sort(key=lambda x: _SEVERITY_ORDER.get(x["severity"], 99))

__all__ = ["TASK3_GROUND_TRUTH"]
