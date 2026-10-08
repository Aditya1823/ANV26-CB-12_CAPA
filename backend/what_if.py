import copy

from analyzer import find_attack_paths
from risk_engine import calculate_path_risk


# ============================================================
# APPLY ONE REMEDIATION
# ============================================================

def apply_remediation(
    graph,
    remediation
):
    action = remediation.action
    resource = remediation.resource
    target = remediation.target

    # --------------------------------------------------------
    # REMOVE INTERNET EXPOSURE
    # --------------------------------------------------------

    if action == "REMOVE_INTERNET_EXPOSURE":

        if resource in graph.nodes:

            graph.nodes[
                resource
            ]["internet_exposed"] = False

    # --------------------------------------------------------
    # REDUCE EXCESSIVE PERMISSION
    # --------------------------------------------------------

    elif action == "REDUCE_EXCESSIVE_PERMISSION":

        if resource in graph.nodes:

            graph.nodes[
                resource
            ]["excessive_permission"] = False

            edges_to_remove = []

            for (
                source,
                destination,
                edge_data
            ) in list(
                graph.edges(
                    resource,
                    data=True
                )
            ):

                if edge_data.get(
                    "type"
                ) == "permission":

                    edges_to_remove.append(
                        (
                            source,
                            destination
                        )
                    )

            for (
                source,
                destination
            ) in edges_to_remove:

                if graph.has_edge(
                    source,
                    destination
                ):

                    graph.remove_edge(
                        source,
                        destination
                    )

    # --------------------------------------------------------
    # REMOVE ADMIN PERMISSION
    # --------------------------------------------------------

    elif action == "REMOVE_ADMIN_PERMISSION":

        if resource in graph.nodes:

            graph.nodes[
                resource
            ]["admin_permission"] = False

            edges_to_remove = []

            for (
                source,
                destination,
                edge_data
            ) in list(
                graph.edges(
                    resource,
                    data=True
                )
            ):

                if edge_data.get(
                    "type"
                ) == "permission":

                    edges_to_remove.append(
                        (
                            source,
                            destination
                        )
                    )

            for (
                source,
                destination
            ) in edges_to_remove:

                if graph.has_edge(
                    source,
                    destination
                ):

                    graph.remove_edge(
                        source,
                        destination
                    )

    # --------------------------------------------------------
    # REMOVE PUBLIC ACCESS
    # --------------------------------------------------------

    elif action == "REMOVE_PUBLIC_ACCESS":

        if resource in graph.nodes:

            graph.nodes[
                resource
            ]["public_access"] = False

    # --------------------------------------------------------
    # REMOVE DANGEROUS CONNECTION
    # --------------------------------------------------------

    elif action == "REMOVE_DANGEROUS_CONNECTION":

        if (
            target
            and graph.has_edge(
                resource,
                target
            )
        ):

            graph.remove_edge(
                resource,
                target
            )

    return graph


# ============================================================
# SIMULATE MULTIPLE REMEDIATIONS
# ============================================================

def simulate_remediation_set(
    graph,
    remediations
):
    """
    Applies a complete remediation strategy
    to a copy of the original graph.
    """

    simulated_graph = copy.deepcopy(
        graph
    )

    for remediation in remediations:

        simulated_graph = apply_remediation(
            simulated_graph,
            remediation
        )

    # --------------------------------------------------------
    # Recalculate attack paths
    # --------------------------------------------------------

    remaining_paths = find_attack_paths(
        simulated_graph
    )

    results = []

    for attack_path in remaining_paths:

        risk = calculate_path_risk(
            simulated_graph,
            attack_path["path"]
        )

        results.append({

            "entry_point":
                attack_path["entry_point"],

            "target":
                attack_path["target"],

            "path":
                attack_path["path"],

            "risk_score":
                risk["score"],

            "severity":
                risk["severity"],

            "reasons":
                risk["reasons"],
        })

    return {
        "remaining_attack_paths":
            len(results),

        "paths":
            results,

        "path_broken":
            len(results) == 0,
    }


# ============================================================
# SINGLE REMEDIATION
# ============================================================

def simulate_remediation(
    graph,
    remediation
):
    """
    Backward-compatible wrapper for the
    original single-fix simulation.
    """

    return simulate_remediation_set(
        graph,
        [remediation]
    )