"""
Security Analysis Engine

Internal modules that enhance the vulnerability scanner with
dependency analysis, static pattern detection, dataflow tracking,
exploitability evaluation, and attack chain detection.

These modules run internally and do NOT change the agent API.
"""

from .dependency_graph import build_dependency_graph
from .static_analysis import run_static_analysis
from .dataflow_analysis import analyze_dataflows
from .exploitability import evaluate_exploitability
from .attack_chain import detect_attack_chains