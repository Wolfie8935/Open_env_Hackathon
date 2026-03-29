"""
Attack Chain Detector

Combines multiple vulnerability signals to identify
multi-step security attack paths.
"""

from typing import Dict, List

def detect_attack_chains(dependency_graph: Dict[str, List[str]],
                         exploitability_results: Dict[str, List[dict]]) -> List[dict]:
    """
    Detect potential multi-step attack chains.

    Returns:
        [
            {
                "files": [str],
                "chain_type": str,
                "severity": str
            }
        ]
    """

    chains: List[dict] = []

    for file, risks in exploitability_results.items():
        for risk in risks:
            if['risk_score'] >= 0.7:
                if risk['category'] == "filesystem_access":
                    chains.append({
                        "files": [file],
                        "chain_type": "path_traversal_chain",
                        "severity": "high"
                    })

                elif risk['category'] == "network_access":
                    chains.append({
                        "files": [file],
                        "chain_type": "ssrf_chain",
                        "severity": "high"
                    })
                
                elif risk['category'] == "deserialization":
                    chains.append({
                        "files": [file],
                        "chain_type": "deserialization_rce_chain",
                        "severity": "critical"
                    })

        if file in dependency_graph:
            deps = dependency_graph[file]

            for dep in deps:
                if dep in exploitability_results:
                    for dep_risk in exploitability_results[dep]:
                        if dep_risk['risk_score'] >= 0.7:
                            chains.append({
                                "files": [file, dep],
                                "chain_type": "multi_file_attack_chain",
                                "severity": "critical"
                            })

    return chains