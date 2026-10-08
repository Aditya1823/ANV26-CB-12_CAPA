def calculate_path_risk(graph, path):
    """
    Calculate a deterministic risk score for an attack path.
    """

    score = 0
    reasons = []

    for node in path:
        data = graph.nodes[node]

        # Internet exposure
        if data.get("internet_exposed", False):
            score += 30
            reasons.append(
                f"{node} is internet exposed (+30)"
            )

        # Excessive permission
        if data.get("excessive_permission", False):
            score += 30
            reasons.append(
                f"{node} has excessive permissions (+30)"
            )

        # Admin permission
        if data.get("admin_permission", False):
            score += 30
            reasons.append(
                f"{node} has admin-level permissions (+30)"
            )

        # Public access
        if data.get("public_access", False):
            score += 20
            reasons.append(
                f"{node} has public access (+20)"
            )

        # Critical asset
        if data.get("critical", False):
            score += 30
            reasons.append(
                f"{node} is a critical asset (+30)"
            )

    # Additional dangerous edges
    for source, target in zip(path, path[1:]):
        edge_data = graph.edges[source, target]

        if edge_data.get("dangerous", False):
            score += 20
            reasons.append(
                f"{source} → {target} contains a dangerous connection (+20)"
            )

    # Severity mapping
    if score >= 90:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "score": score,
        "severity": severity,
        "reasons": reasons
    }