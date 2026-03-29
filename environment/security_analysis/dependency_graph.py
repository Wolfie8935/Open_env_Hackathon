"""
Dependency Graph Builder
Builds a file-level dependency graph from Python source code.
Internal module used by the environment to understand file relationships.
"""

import ast
from typing import Dict, List

def build_dependency_graph(files: Dict[str, str]) -> Dict[str, List[str]]:
    """
    Build dependency graph from a dictionary of Python files.

    Args:
        files: dict[str, str]
            Mapping of filename -> source code

    Returns:
        dict[str, list[str]]
            Mapping of file -> list of files it depends on
    """

    graph: Dict[str, List[str]] = {}

    module_to_file = {
        filename.replace(".py",""): filename
        for filename in files.keys()
    }

    for filename, code in files.items():
        dependencies: List[str] = []

        try:
            tree = ast.parse(code)
        except SyntaxError:
            graph[filename] = []
            continue

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module = alias.name.split(".")[0]
                    if module in module_to_file:
                        dependencies.append(module_to_file[module])

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    module = node.module.split(".")[0]
                    if module in module_to_file:
                        dependencies.append(module_to_file[module])

        graph[filename] = sorted(set(dependencies))

    return graph
