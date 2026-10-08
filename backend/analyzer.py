import networkx as nx


def find_attack_paths(graph: nx.DiGraph):
    """
    Find attack paths from internet-exposed resources
    to critical resources.
    """

    entry_points = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("internet_exposed", False)
    ]

    critical_assets = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("critical", False)
    ]

    attack_paths = []

    for entry in entry_points:
        for target in critical_assets:

            if not nx.has_path(graph, entry, target):
                continue

            paths = nx.all_simple_paths(
                graph,
                source=entry,
                target=target
            )

            for path in paths:
                attack_paths.append({
                    "entry_point": entry,
                    "target": target,
                    "path": path,
                    "length": len(path) - 1
                })

    return attack_paths