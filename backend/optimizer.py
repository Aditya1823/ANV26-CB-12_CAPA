import itertools

from models import RemediationAction
from remediation import generate_remediations
from what_if import simulate_remediation


# ============================================================
# BUSINESS DISRUPTION MODEL
# ============================================================

DISRUPTION_SCORES = {
    "REMOVE_INTERNET_EXPOSURE": 8,
    "REDUCE_EXCESSIVE_PERMISSION": 3,
    "REMOVE_ADMIN_PERMISSION": 5,
    "REMOVE_PUBLIC_ACCESS": 6,
    "REMOVE_DANGEROUS_CONNECTION": 7,
}


def disruption_cost(remediation):
    return DISRUPTION_SCORES.get(
        remediation.action,
        5
    )


# ============================================================
# CREATE UNIQUE REMEDIATION CANDIDATES
# ============================================================

def collect_candidates(graph, attack_paths):

    candidates = {}

    for attack_path in attack_paths:

        recommendations = generate_remediations(
            graph,
            attack_path["path"]
        )

        for recommendation in recommendations:

            remediation = RemediationAction(
                action=recommendation["action"],
                resource=recommendation["resource"],
                target=recommendation.get("target")
            )

            key = (
                remediation.action,
                remediation.resource,
                remediation.target
            )

            candidates[key] = {
                "remediation": remediation,
                "action": recommendation["action"],
                "resource": recommendation["resource"],
                "target": recommendation.get("target"),
                "description": recommendation["description"],
                "disruption_cost": disruption_cost(
                    remediation
                )
            }

    return list(candidates.values())


# ============================================================
# SIMULATE A SET OF REMEDIATIONS
# ============================================================

def simulate_remediation_set(
    graph,
    remediation_set
):
    """
    Apply multiple remediation actions sequentially
    to a copied graph.

    Each simulation starts from the graph produced
    by the previous remediation.
    """

    import copy

    simulated_graph = copy.deepcopy(graph)

    for candidate in remediation_set:

        remediation = candidate["remediation"]

        # Import here to avoid changing the existing
        # what_if.py architecture.
        from what_if import simulate_remediation

        # simulate_remediation returns results but
        # does not expose the modified graph.
        #
        # Therefore apply the remediation directly
        # to the working graph.

        action = remediation.action
        resource = remediation.resource
        target = remediation.target

        if action == "REMOVE_INTERNET_EXPOSURE":

            if resource in simulated_graph.nodes:

                simulated_graph.nodes[
                    resource
                ]["internet_exposed"] = False

        elif action == "REDUCE_EXCESSIVE_PERMISSION":

            if resource in simulated_graph.nodes:

                simulated_graph.nodes[
                    resource
                ]["excessive_permission"] = False

                edges_to_remove = []

                for source, destination, edge_data in list(
                    simulated_graph.edges(
                        resource,
                        data=True
                    )
                ):

                    if edge_data.get("type") == "permission":

                        edges_to_remove.append(
                            (source, destination)
                        )

                for source, destination in edges_to_remove:

                    if simulated_graph.has_edge(
                        source,
                        destination
                    ):
                        simulated_graph.remove_edge(
                            source,
                            destination
                        )

        elif action == "REMOVE_ADMIN_PERMISSION":

            if resource in simulated_graph.nodes:

                simulated_graph.nodes[
                    resource
                ]["admin_permission"] = False

                edges_to_remove = []

                for source, destination, edge_data in list(
                    simulated_graph.edges(
                        resource,
                        data=True
                    )
                ):

                    if edge_data.get("type") == "permission":

                        edges_to_remove.append(
                            (source, destination)
                        )

                for source, destination in edges_to_remove:

                    if simulated_graph.has_edge(
                        source,
                        destination
                    ):
                        simulated_graph.remove_edge(
                            source,
                            destination
                        )

        elif action == "REMOVE_PUBLIC_ACCESS":

            if resource in simulated_graph.nodes:

                simulated_graph.nodes[
                    resource
                ]["public_access"] = False

        elif action == "REMOVE_DANGEROUS_CONNECTION":

            if (
                target
                and simulated_graph.has_edge(
                    resource,
                    target
                )
            ):

                simulated_graph.remove_edge(
                    resource,
                    target
                )

    return simulated_graph


# ============================================================
# OPTIMIZATION
# ============================================================

def optimize_remediations(
    graph,
    attack_paths
):

    if not attack_paths:
        return []

    candidates = collect_candidates(
        graph,
        attack_paths
    )

    if not candidates:
        return []

    results = []

    # --------------------------------------------------------
    # Evaluate combinations up to 3 fixes.
    #
    # This keeps the optimizer fast while allowing
    # meaningful multi-remediation optimization.
    # --------------------------------------------------------

    max_combination_size = min(
        3,
        len(candidates)
    )

    for size in range(
        1,
        max_combination_size + 1
    ):

        for combination in itertools.combinations(
            candidates,
            size
        ):

            simulated_graph = simulate_remediation_set(
                graph,
                combination
            )

            # ------------------------------------------------
            # Recalculate attack paths
            # ------------------------------------------------

            from analyzer import find_attack_paths
            from risk_engine import calculate_path_risk

            remaining_paths = find_attack_paths(
                simulated_graph
            )

            remaining_risk_scores = []

            for path in remaining_paths:

                risk = calculate_path_risk(
                    simulated_graph,
                    path["path"]
                )

                remaining_risk_scores.append(
                    risk["score"]
                )

            remaining_path_count = len(
                remaining_paths
            )

            original_path_count = len(
                attack_paths
            )

            broken_paths = (
                original_path_count
                - remaining_path_count
            )

            path_break_percentage = round(
                (
                    broken_paths
                    / max(original_path_count, 1)
                ) * 100,
                2
            )

            total_disruption = sum(
                item["disruption_cost"]
                for item in combination
            )

            max_remaining_risk = max(
                remaining_risk_scores,
                default=0
            )

            security_score = round(
                (
                    broken_paths
                    / max(original_path_count, 1)
                ) * 100,
                2
            )

            # Higher security + lower disruption = better
            efficiency_score = round(
                security_score
                / max(total_disruption, 1),
                2
            )

            path_broken = (
                remaining_path_count == 0
            )

            results.append({

                "actions": [
                    {
                        "action": item["action"],
                        "resource": item["resource"],
                        "target": item["target"],
                        "description": item["description"],
                    }
                    for item in combination
                ],

                "action_count": len(
                    combination
                ),

                "description": (
                    " + ".join(
                        item["description"]
                        for item in combination
                    )
                ),

                "disruption_cost":
                    total_disruption,

                "original_attack_paths":
                    original_path_count,

                "remaining_attack_paths":
                    remaining_path_count,

                "broken_attack_paths":
                    broken_paths,

                "path_break_percentage":
                    path_break_percentage,

                "security_score":
                    security_score,

                "remaining_risk":
                    max_remaining_risk,

                "efficiency_score":
                    efficiency_score,

                "path_broken":
                    path_broken,
            })

    # ========================================================
    # RANKING
    # ========================================================

    results.sort(
        key=lambda item: (
            item["path_broken"],
            item["broken_attack_paths"],
            item["efficiency_score"],
            item["security_score"],
            -item["disruption_cost"],
        ),
        reverse=True
    )

    # ========================================================
    # REMOVE DUPLICATE / DOMINATED RESULTS
    # ========================================================

    unique_results = []

    seen = set()

    for result in results:

        action_key = tuple(
            sorted(
                (
                    action["action"],
                    action["resource"],
                    action.get("target")
                )
                for action in result["actions"]
            )
        )

        if action_key in seen:
            continue

        seen.add(action_key)

        unique_results.append(
            result
        )

    # Keep the most useful recommendations
    return unique_results[:10]