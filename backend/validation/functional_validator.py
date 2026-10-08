import networkx as nx


def validate_functional_impact(
    original_graph: nx.DiGraph,
    remediated_graph: nx.DiGraph,
) -> dict:
    """
    Compare the original and remediated synthetic security graphs.

    This does not interact with real infrastructure.
    """

    original_edges = set(original_graph.edges())
    remediated_edges = set(remediated_graph.edges())

    removed_edges = sorted(original_edges - remediated_edges)
    added_edges = sorted(remediated_edges - original_edges)

    legitimate_relationships_broken = []

    for source, target in removed_edges:
        edge_data = original_graph.edges[source, target]

        if not edge_data.get("dangerous", False):
            legitimate_relationships_broken.append({
                "source": source,
                "target": target,
                "type": edge_data.get("type"),
                "permission": edge_data.get("permission"),
            })

    return {
        "functional_status": (
            "IMPACT_DETECTED"
            if legitimate_relationships_broken
            else "NO_SIGNIFICANT_IMPACT"
        ),
        "removed_relationship_count": len(removed_edges),
        "added_relationship_count": len(added_edges),
        "removed_relationships": [
            {
                "source": source,
                "target": target,
            }
            for source, target in removed_edges
        ],
        "added_relationships": [
            {
                "source": source,
                "target": target,
            }
            for source, target in added_edges
        ],
        "legitimate_relationships_broken": legitimate_relationships_broken,
        "legitimate_relationships_broken_count": len(
            legitimate_relationships_broken
        ),
    }
