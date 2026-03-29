"""
Dataflow Analysis Engine

Tracks how variables flow through functions to detect
potential security-sensitive data paths.
"""

import ast
from typing import Dict, List

def analyze_dataflows(files: Dict[str, str]) -> Dict[str, List[dict]]:

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
                        "risk": "filesystem_access"
                    })

                # requests.get()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "get":
                        flows.append({
                            "source": "variable_input",
                            "sink": "requests.get",
                            "line": node.lineno,
                            "risk": "network_request"
                        })

                # pickle.loads()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == "loads":
                        flows.append({
                            "source": "variable_input",
                            "sink": "pickle.loads",
                            "line": node.lineno,
                            "risk": "deserialization"
                        })

        results[filename] = flows

    return results