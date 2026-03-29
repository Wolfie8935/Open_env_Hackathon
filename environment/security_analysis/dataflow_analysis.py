"""
Dataflow Analysis Engine

Tracks how variables flow through functions to detect
potential security-sensitive data paths.

Per-file results are capped at 3 entries to avoid flooding
the agent with noise when many flows are detected in one file.
"""

import ast
from typing import Dict, List

_MAX_FLOWS_PER_FILE = 3

# Risk weights for sorting (higher risk first)
_RISK_WEIGHTS: Dict[str, float] = {
    "deserialization": 1.0,
    "filesystem_access": 0.8,
    "network_request": 0.7,
}


def analyze_dataflows(files: Dict[str, str]) -> Dict[str, List[dict]]:
    """Analyze dataflows in all provided source files.

    Returns a dict mapping filename → list of flow entries (capped to 3 per file).
    """
    results: Dict[str, List[dict]] = {}

    for filename, code in files.items():
        flows: List[dict] = []

        try:
            tree = ast.parse(code)
        except SyntaxError:
            results[filename] = []
            continue

        for node in ast.walk(tree):

            if isinstance(node, ast.Call):

                # open()
                if isinstance(node.func, ast.Name) and node.func.id == "open":
                    flows.append({
                        "source": "variable_input",
                        "sink": "open",
                        "line": node.lineno,
                        "risk": "filesystem_access",
                        "risk_weight": _RISK_WEIGHTS["filesystem_access"],
                    })

                # requests.get()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "get":
                        flows.append({
                            "source": "variable_input",
                            "sink": "requests.get",
                            "line": node.lineno,
                            "risk": "network_request",
                            "risk_weight": _RISK_WEIGHTS["network_request"],
                        })

                # pickle.loads()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "loads":
                        flows.append({
                            "source": "variable_input",
                            "sink": "pickle.loads",
                            "line": node.lineno,
                            "risk": "deserialization",
                            "risk_weight": _RISK_WEIGHTS["deserialization"],
                        })

        # Cap to top-N highest-risk flows per file
        flows_sorted = sorted(flows, key=lambda x: x.get("risk_weight", 0), reverse=True)
        results[filename] = flows_sorted[:_MAX_FLOWS_PER_FILE]

    return results