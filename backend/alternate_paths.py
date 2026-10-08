import networkx as nx


def find_alternate_paths(graph: nx.DiGraph, path):
    """
    Find alternate attack paths between the same entry point
    and critical target while excluding the primary path.
    """

    if len(path) < 2:
        return []

    source = path[0]
    target = path[-1]

    alternate_paths = []

    # Find all simple paths between the same entry and target
    try:
        all_paths = nx.all_simple_paths(
            graph,
            source=source,
            target=target
        )
    except nx.NetworkXNoPath:
        return []

    primary_path = tuple(path)

    for candidate in all_paths:

        candidate_tuple = tuple(candidate)

        # Ignore the original path
        if candidate_tuple == primary_path:
            continue

        alternate_paths.append({
            "path": candidate,
            "length": len(candidate) - 1
        })

    return alternate_paths