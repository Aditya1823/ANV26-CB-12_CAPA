import networkx as nx


def validate_attack_path(graph: nx.DiGraph, path: list[str]) -> dict:
    if not path:
        return {
            "status": "NOT_VALIDATED",
            "validated": False,
            "reason": "Empty attack path",
            "checks": [],
            "simulation_type": "CONTROLLED_SYNTHETIC",
        }

    entry = path[0]
    target = path[-1]
    checks = []

    entry_exists = entry in graph.nodes
    entry_exposed = (
        entry_exists
        and graph.nodes[entry].get("internet_exposed", False)
    )

    checks.append({
        "check": "entry_point_exists",
        "passed": entry_exists,
        "details": entry,
    })

    checks.append({
        "check": "entry_point_exposed",
        "passed": entry_exposed,
        "details": "Internet exposed" if entry_exposed else "Not internet exposed",
    })

    nodes_valid = all(node in graph.nodes for node in path)

    checks.append({
        "check": "all_nodes_exist",
        "passed": nodes_valid,
        "details": f"{len(path)} path nodes checked",
    })

    relationships_valid = True

    for source, destination in zip(path, path[1:]):
        exists = graph.has_edge(source, destination)

        if not exists:
            relationships_valid = False

        checks.append({
            "check": "relationship_exists",
            "passed": exists,
            "details": f"{source} -> {destination}",
        })

    target_is_critical = (
        target in graph.nodes
        and graph.nodes[target].get("critical", False)
    )

    checks.append({
        "check": "critical_target",
        "passed": target_is_critical,
        "details": target,
    })

    validated = all([
        entry_exists,
        entry_exposed,
        nodes_valid,
        relationships_valid,
        target_is_critical,
    ])

    return {
        "status": "VALIDATED" if validated else "NOT_VALIDATED",
        "validated": validated,
        "entry_point": entry,
        "target": target,
        "path": path,
        "checks": checks,
        "reason": (
            "Controlled graph validation confirms the supplied "
            "reachability chain."
            if validated
            else "Controlled graph validation could not confirm the complete chain."
        ),
        "simulation_type": "CONTROLLED_SYNTHETIC",
    }
