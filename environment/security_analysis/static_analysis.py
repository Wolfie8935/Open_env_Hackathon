"""
Static Security Analyzer

Performs lightweight static pattern detection on Python files.
Used internally to guide deeper vulnerability analysis.
"""

import ast
from typing import Dict, List

def run_static_analysis(files: Dict[str, str]) -> Dict[str, List[dict]]:

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
                        "type": "command_injection"
                    })

                if node.func.id == "exec":
                    findings.append({
                        "line": node.lineno,
                        "type": "command_injection"
                    })

            # attribute calls like pickle.loads, os.system, os.path.join
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):

                if node.func.attr == "loads":
                    findings.append({
                        "line": node.lineno,
                        "type": "insecure_deserialization"
                    })

                if node.func.attr == "system":
                    findings.append({
                        "line": node.lineno,
                        "type": "command_injection"
                    })

                if node.func.attr == "join":
                    findings.append({
                        "line": node.lineno,
                        "type": "path_traversal_candidate"
                    })

        results[filename] = findings

    return results