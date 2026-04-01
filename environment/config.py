"""
Feature flags for safe, backward-compatible rollout of new scoring features.
All flags default to OFF to preserve existing behavior.
"""

ENABLE_EVIDENCE_MODE = False
ENABLE_ADVERSARIAL_TRAPS = True
ENABLE_PRECISION_SCORING = True
ENABLE_ANTI_GAMING_ESCALATION = True

