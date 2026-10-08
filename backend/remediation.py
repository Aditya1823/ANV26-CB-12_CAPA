import networkx as nx


def generate_remediations(graph: nx.DiGraph, path):
    """
    Generate remediation recommendations for a dangerous attack path.
    """

    recommendations = []

    for node in path:
        data = graph.nodes[node]

        if data.get("internet_exposed", False):
            recommendations.append({
                "action": "REMOVE_INTERNET_EXPOSURE",
                "resource": node,
                "description": f"Remove internet exposure from {node}",
                "priority": "HIGH"
            })

        if data.get("excessive_permission", False):
            recommendations.append({
                "action": "REDUCE_EXCESSIVE_PERMISSION",
                "resource": node,
                "description": f"Reduce excessive permissions on {node}",
                "priority": "CRITICAL"
            })

        if data.get("admin_permission", False):
            recommendations.append({
                "action": "REMOVE_ADMIN_PERMISSION",
                "resource": node,
                "description": f"Remove unnecessary admin permissions from {node}",
                "priority": "CRITICAL"
            })

        if data.get("public_access", False):
            recommendations.append({
                "action": "REMOVE_PUBLIC_ACCESS",
                "resource": node,
                "description": f"Remove public access from {node}",
                "priority": "HIGH"
            })

    # Dangerous connections can also be remediation targets
    for source, target in zip(path, path[1:]):
        edge_data = graph.edges[source, target]

        if edge_data.get("dangerous", False):
            recommendations.append({
                "action": "REMOVE_DANGEROUS_CONNECTION",
                "resource": source,
                "target": target,
                "description": (
                    f"Remove dangerous connection "
                    f"from {source} to {target}"
                ),
                "priority": "HIGH"
            })

    return recommendations