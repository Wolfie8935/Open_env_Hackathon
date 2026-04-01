from typing import Dict, List, Tuple

#Chain Pattern Definitions
# These patterns define logical exploit progressions.
# They are intentionally simple to keep runtime negligible.
CHAIN_REASONING_PATTERNS: List[Tuple[str, str]] = [
    ("network_request", "deserialization"),
    ("network_request", "filesystem_access"),
    ("filesystem_access", "deserialization"),
]

#Utility
def _risk_categories_above_threshold(risks: List[dict], threshold: float = 0.7) -> List[str]:
    """Return risk categories that exceed the threshold."""
    return [r["category"] for r in risks if r.get("risk_score", 0) >= threshold]

#Core Chain Detection
def detect_attack_chains(
    dependency_graph: Dict[str, List[str]],
    exploitability_results: Dict[str, List[dict]],
) -> List[dict]:
    """
    Detect attack chains from exploitability results.

    Extensions added:
    - Multi-step exploit reasoning
    - Deterministic ordering
    - Reasoning metadata

    Fully backward compatible with existing system.
    """

    raw_chains: List[dict] = []

    #Single-file exploit chains
    for file, risks in exploitability_results.items():

        for risk in risks:

            if risk["risk_score"] >= 0.7:

                if risk["category"] == "filesystem_access":
                    raw_chains.append({
                        "files": [file],
                        "chain_type": "path_traversal_chain",
                        "severity": "high",
                        "reasoning": "filesystem access risk enables path traversal",
                    })

                elif risk["category"] == "network_request":
                    raw_chains.append({
                        "files": [file],
                        "chain_type": "ssrf_chain",
                        "severity": "high",
                        "reasoning": "untrusted network request enables SSRF",
                    })

                elif risk["category"] == "deserialization":
                    raw_chains.append({
                        "files": [file],
                        "chain_type": "deserialization_rce_chain",
                        "severity": "critical",
                        "reasoning": "unsafe deserialization may lead to RCE",
                    })

    #Multi-file attack chains
    for file in dependency_graph:

        deps = dependency_graph.get(file, [])

        for dep in deps:

            if dep not in exploitability_results:
                continue

            file_risks = exploitability_results.get(file, [])
            dep_risks = exploitability_results.get(dep, [])

            for dep_risk in dep_risks:

                if dep_risk["risk_score"] >= 0.7:

                    raw_chains.append({
                        "files": [file, dep],
                        "chain_type": "multi_file_attack_chain",
                        "severity": "critical",
                        "reasoning": "high risk dependency enables chained exploitation",
                    })

                    break

    #Exploit reasoning chains
    for file, risks in exploitability_results.items():

        categories = _risk_categories_above_threshold(risks)

        for step1, step2 in CHAIN_REASONING_PATTERNS:

            if step1 in categories and step2 in categories:

                raw_chains.append({
                    "files": [file],
                    "chain_type": "multi_step_reasoning_chain",
                    "severity": "critical",
                    "reasoning": f"{step1} → {step2} exploitation path",
                })

    #Dependency reasoning chains (cross-file)
    for file, deps in dependency_graph.items():

        file_risks = exploitability_results.get(file, [])
        file_categories = _risk_categories_above_threshold(file_risks)

        for dep in deps:

            dep_risks = exploitability_results.get(dep, [])
            dep_categories = _risk_categories_above_threshold(dep_risks)

            for step1, step2 in CHAIN_REASONING_PATTERNS:

                if step1 in file_categories and step2 in dep_categories:

                    raw_chains.append({
                        "files": [file, dep],
                        "chain_type": "cross_file_reasoning_chain",
                        "severity": "critical",
                        "reasoning": f"{step1} in {file} enables {step2} in {dep}",
                    })

    #Deduplicate chains
    seen: set = set()
    deduped: List[dict] = []

    for chain in raw_chains:

        key = (tuple(sorted(chain["files"])), chain["chain_type"])

        if key not in seen:
            seen.add(key)
            deduped.append(chain)

    #Deterministic ordering
    deduped.sort(key=lambda c: (tuple(sorted(c["files"])), c["chain_type"]))

    return deduped