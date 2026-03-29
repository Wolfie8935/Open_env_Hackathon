"""
Dataflow Analysis Engine

Tracks how variables flow through functions to detect
potential security-sensitive data paths.
"""

import ast
from typing import Dict, List

def analyze_dataflows(files: Dict[str, str]) -> dict[str, List[dict]]:
    """
    Analyze variable flows inside Python files.

    Returns:
        {
            filename: [
                {
                    "source": str,
                    "sink": str,
                    "line": int,
                    "risk": str
                }
            ]
        }
    """

    results: Dict[str,List[dict]] = {}

    for filename, code in files.items():
        flows: List[dict] = []

        try:
            tree = ast.aprse(code)
        except SyntaxError:
            results[filename] = []
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id=='open':
                    flows.append({
                        "source": "variable_input",
                        "sink": "open",
                        "line": node.lineno,
                        "risk": "filesystem_access"
                    })

                if isinstance(node.func, ast.Attribute):
                    if node.func.attr=='get':
                        flows.append({
                            "source": "variable_input",
                            "sink": "requests.get",
                            "line": node.lineno,
                            "risk": "netwoek_request"
                        })

                if isinstance(node.func, ast.Attribute):
                    if node.func.attr=='loads':
                        flows.append({
                            "source": "varibale_input",
                            "sink": "pickle.loads",
                            "line": node.lineno,
                            "risk": "deserialization"
                        })
        
        results[filename] = flows

    return results