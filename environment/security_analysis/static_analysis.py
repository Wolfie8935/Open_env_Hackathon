"""
Static Security Analyzer

Performs lightweight static pattern detection on Python files.
Used internally to guide deeper vulnerability analysis.

Per-file results are capped at 3 entries (highest risk first) to avoid
flooding the agent with noise when many patterns are found in one file.
"""

import ast
from typing import Dict, List

_MAX_HINTS_PER_FILE = 3

# Risk weights for sorting (higher = more interesting to the agent)
_TYPE_RISK: Dict[str, float] = {
    "command_injection": 1.0,
    "insecure_deserialization": 0.9,
    "path_traversal_candidate": 0.7,
}


def run_static_analysis(files: Dict[str, str]) -> Dict[str, List[dict]]:
    """Run lightweight static analysis on all provided source files.

    Returns a dict mapping filename → list of findings (capped to 3 per file).
    """
    results: Dict[str, List[dict]] = {}

    for filename, code in files.items():
        findings: List[dict] = []

        try:
            tree = ast.parse(code)
        except SyntaxError:
            results[filename] = []
            continue

        for node in ast.walk(tree):

            # eval() or exec()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):

                if node.func.id == "eval":
                    findings.append({
                        "line": node.lineno,
                        "type": "command_injection",
                        "risk_score": _TYPE_RISK["command_injection"],
                    })

                if node.func.id == "exec":
                    findings.append({
                        "line": node.lineno,
                        "type": "command_injection",
                        "risk_score": _TYPE_RISK["command_injection"],
                    })

            # attribute calls like pickle.loads, os.system, os.path.join
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):

                if node.func.attr == "loads":
                    findings.append({
                        "line": node.lineno,
                        "type": "insecure_deserialization",
                        "risk_score": _TYPE_RISK["insecure_deserialization"],
                    })

                if node.func.attr == "system":
                    findings.append({
                        "line": node.lineno,
                        "type": "command_injection",
                        "risk_score": _TYPE_RISK["command_injection"],
                    })

                if node.func.attr == "join":
                    findings.append({
                        "line": node.lineno,
                        "type": "path_traversal_candidate",
                        "risk_score": _TYPE_RISK["path_traversal_candidate"],
                    })

        # Cap to top-N highest-risk entries per file
        findings_sorted = sorted(findings, key=lambda x: x.get("risk_score", 0), reverse=True)
        results[filename] = findings_sorted[:_MAX_HINTS_PER_FILE]

    return results