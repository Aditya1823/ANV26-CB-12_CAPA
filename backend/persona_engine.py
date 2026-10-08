from personas import PERSONAS


def score_path_for_persona(graph, path, persona_id):
    """
    Score an attack path according to an adversary persona.
    """

    if persona_id not in PERSONAS:
        raise ValueError(f"Unknown persona: {persona_id}")

    persona = PERSONAS[persona_id]
    weights = persona["weights"]

    score = 0
    factors = []

    for node in path:
        data = graph.nodes[node]

        if data.get("internet_exposed", False):
            contribution = 30 * weights["internet_exposed"]
            score += contribution
            factors.append({
                "resource": node,
                "factor": "internet_exposed",
                "contribution": contribution
            })

        if data.get("excessive_permission", False):
            contribution = 30 * weights["excessive_permission"]
            score += contribution
            factors.append({
                "resource": node,
                "factor": "excessive_permission",
                "contribution": contribution
            })

        if data.get("admin_permission", False):
            contribution = 30 * weights["admin_permission"]
            score += contribution
            factors.append({
                "resource": node,
                "factor": "admin_permission",
                "contribution": contribution
            })

        if data.get("critical", False):
            contribution = 30 * weights["critical_asset"]
            score += contribution
            factors.append({
                "resource": node,
                "factor": "critical_asset",
                "contribution": contribution
            })

    return {
        "persona": persona["name"],
        "description": persona["description"],
        "persona_score": round(score, 2),
        "factors": factors
    }


def rank_paths_by_persona(graph, attack_paths, persona_id):
    """
    Rank attack paths according to an adversary persona.
    """

    ranked_paths = []

    for attack_path in attack_paths:

        persona_result = score_path_for_persona(
            graph,
            attack_path["path"],
            persona_id
        )

        ranked_paths.append({
            "entry_point": attack_path["entry_point"],
            "target": attack_path["target"],
            "path": attack_path["path"],
            **persona_result
        })

    ranked_paths.sort(
        key=lambda item: item["persona_score"],
        reverse=True
    )

    return ranked_paths