import networkx as nx


def calculate_blast_radius(graph: nx.DiGraph, path):
    """
    Calculate downstream resources affected by a compromised attack path.
    """

    affected_resources = set()
    critical_resources = set()

    # Start from every node on the attack path
    for node in path:

        descendants = nx.descendants(graph, node)

        for resource in descendants:
            affected_resources.add(resource)

    # Include the attack-path nodes themselves
    affected_resources.update(path)

    # Find critical resources inside the affected area
    for resource in affected_resources:

        if graph.nodes[resource].get("critical", False):
            critical_resources.add(resource)

    return {
        "affected_resource_count": len(affected_resources),
        "affected_resources": sorted(affected_resources),
        "critical_resources": sorted(critical_resources),
        "critical_resource_count": len(critical_resources)
    }