from typing import Any, Dict, List


SEVERITY_ORDER = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFO": 0,
}


def normalize_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "finding_id": finding.get("finding_id", "FND-UNKNOWN"),
        "type": finding.get("type", "UNKNOWN"),
        "severity": str(finding.get("severity", "LOW")).upper(),
        "confidence": str(finding.get("confidence", "MEDIUM")).upper(),
        "resource": finding.get("resource"),
        "file": finding.get("file"),
        "line": finding.get("line"),
        "description": finding.get("description", ""),
        "impact": finding.get("impact", ""),
        "evidence": finding.get("evidence"),
        "remediation": finding.get("remediation", ""),
    }


def build_findings(
    configuration_findings: List[Dict[str, Any]] | None = None,
    secret_findings: List[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    findings = []

    for finding in configuration_findings or []:
        findings.append(normalize_finding(finding))

    for finding in secret_findings or []:
        normalized = normalize_finding(finding)

        if not normalized["impact"]:
            normalized["impact"] = (
                "An exposed credential may allow unauthorized access "
                "to a protected resource or service."
            )

        findings.append(normalized)

    findings.sort(
        key=lambda item: SEVERITY_ORDER.get(item["severity"], 0),
        reverse=True,
    )

    return findings


def summarize_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "LOW")
        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "total_findings": len(findings),
        "critical_findings": severity_counts["CRITICAL"],
        "high_findings": severity_counts["HIGH"],
        "medium_findings": severity_counts["MEDIUM"],
        "low_findings": severity_counts["LOW"],
        "severity_counts": severity_counts,
    }
