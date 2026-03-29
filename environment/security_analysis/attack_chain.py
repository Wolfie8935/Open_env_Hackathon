from typing import Dict, List


def detect_attack_chains(
    dependency_graph: Dict[str, List[str]],
    exploitability_results: Dict[str, List[dict]],
) -> List[dict]:
    """Detect attack chains from exploitability results.

    Deduplicates by (files, chain_type) to avoid noise from repeated
    ssrf_chain / deserialization_rce_chain entries for the same file.
    """
    raw_chains: List[dict] = []

    for file, risks in exploitability_results.items():

        for risk in risks:

            if risk["risk_score"] >= 0.7:

                if risk["category"] == "filesystem_access":
                    raw_chains.append({
                        "files": [file],
                        "chain_type": "path_traversal_chain",
                        "severity": "high",
                    })

                elif risk["category"] == "network_request":
                    raw_chains.append({
                        "files": [file],
                        "chain_type": "ssrf_chain",
                        "severity": "high",
                    })

                elif risk["category"] == "deserialization":
                    raw_chains.append({
                        "files": [file],
                        "chain_type": "deserialization_rce_chain",
                        "severity": "critical",
                    })

        # Multi-file attack chain detection (capped at 1 per file pair)
        if file in dependency_graph:
            deps = dependency_graph[file]

            for dep in deps:
                if dep in exploitability_results:

                    for dep_risk in exploitability_results[dep]:

                        if dep_risk["risk_score"] >= 0.7:
                            raw_chains.append({
                                "files": [file, dep],
                                "chain_type": "multi_file_attack_chain",
                                "severity": "critical",
                            })
                            # Only add one multi-file chain per (file, dep) pair
                            break

    # ── Deduplicate by (frozenset of files, chain_type) ───────
    seen: set = set()
    deduped: List[dict] = []
    for chain in raw_chains:
        key = (tuple(sorted(chain["files"])), chain["chain_type"])
        if key not in seen:
            seen.add(key)
            deduped.append(chain)

    return deduped