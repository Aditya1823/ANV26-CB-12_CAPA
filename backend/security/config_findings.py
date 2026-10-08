from typing import List

from models import CloudConfiguration


def detect_configuration_findings(
    configuration: CloudConfiguration,
) -> List[dict]:
    findings = []
    counter = 1

    def add_finding(
        finding_type,
        severity,
        confidence,
        resource,
        description,
        impact,
        remediation,
        evidence,
        target=None,
    ):
        nonlocal counter

        finding = {
            "finding_id": f"FND-{counter:03d}",
            "type": finding_type,
            "severity": severity,
            "confidence": confidence,
            "resource": resource,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "evidence": evidence,
        }

        if target:
            finding["target"] = target

        findings.append(finding)
        counter += 1

    for resource in configuration.resources:
        if resource.internet_exposed:
            add_finding(
                "PUBLIC_EXPOSURE",
                "HIGH",
                "HIGH",
                resource.id,
                f"{resource.id} is directly exposed to the internet.",
                "An externally reachable resource may provide an entry point into the environment.",
                "Remove unnecessary internet exposure or restrict access through appropriate controls.",
                "internet_exposed=true",
            )

        if resource.excessive_permission:
            add_finding(
                "EXCESSIVE_PERMISSION",
                "HIGH",
                "HIGH",
                resource.id,
                f"{resource.id} has excessive permissions.",
                "Excessive permissions can allow unauthorized lateral movement or access to additional resources.",
                "Reduce permissions to the minimum required for the resource.",
                "excessive_permission=true",
            )

        if resource.admin_permission:
            add_finding(
                "ADMIN_PERMISSION",
                "CRITICAL",
                "HIGH",
                resource.id,
                f"{resource.id} has administrative-level permissions.",
                "Administrative privileges can significantly increase the impact of a compromised identity or service.",
                "Remove unnecessary administrative permissions and apply least privilege.",
                "admin_permission=true",
            )

        if resource.public_access:
            add_finding(
                "PUBLIC_ACCESS",
                "HIGH",
                "HIGH",
                resource.id,
                f"{resource.id} allows public access.",
                "Public access can expose protected services or data to untrusted users.",
                "Disable unnecessary public access and restrict access to trusted identities or networks.",
                "public_access=true",
            )

        if resource.critical and resource.sensitivity.lower() in {
            "high",
            "critical",
            "sensitive",
        }:
            add_finding(
                "CRITICAL_SENSITIVE_ASSET",
                "HIGH",
                "HIGH",
                resource.id,
                f"{resource.id} is a critical sensitive asset.",
                "Compromise of this resource may have significant security or business impact.",
                "Apply strong access controls, least privilege, and appropriate monitoring.",
                f"critical=true, sensitivity={resource.sensitivity}",
            )

    for connection in configuration.connections:
        if connection.dangerous:
            add_finding(
                "DANGEROUS_CONNECTION",
                "HIGH",
                "HIGH",
                connection.source,
                (
                    f"{connection.source} has a dangerous connection "
                    f"to {connection.target}."
                ),
                "A dangerous relationship may enable unauthorized movement or access between resources.",
                "Restrict or remove the dangerous relationship where it is not required.",
                (
                    f"type={connection.type}, "
                    f"permission={connection.permission}, "
                    f"dangerous=true"
                ),
                target=connection.target,
            )

    return findings
