from pathlib import Path
from typing import Any, Dict
import json
import yaml

from .file_analyzer import analyze_uploaded_file
from .cloudformation_adapter import is_cloudformation_template, convert_cloudformation
from .analyze_findings import analyze_findings
from ingestion import load_configuration
from graph_builder import build_security_graph
from analyzer import find_attack_paths
from risk_engine import calculate_path_risk
from blast_radius import calculate_blast_radius
from remediation import generate_remediations
from optimizer import optimize_remediations
from persona_engine import rank_paths_by_persona
from alternate_paths import find_alternate_paths
from validation import validate_attack_path


CONFIG_EXTENSIONS = {".json", ".yaml", ".yml"}


def analyze_explicit_file(
    file_name: str,
    content: bytes,
) -> Dict[str, Any]:

    name = Path(file_name).name.lower()
    extension = Path(file_name).suffix.lower()

    # Handle .env explicitly
    if name == ".env" or name.startswith(".env."):
        return analyze_uploaded_file(
            file_name=file_name,
            content=content,
        )

    # JSON/YAML cloud configuration
    if extension in CONFIG_EXTENSIONS:
        try:
            text = content.decode("utf-8")
            if extension == ".json":
                raw_data = json.loads(text)
            else:
                class CloudFormationLoader(yaml.SafeLoader):
                    pass

                def cloudformation_ref(loader, node):
                    return {"Ref": loader.construct_scalar(node)}

                def cloudformation_getatt(loader, node):
                    if isinstance(node, yaml.SequenceNode):
                        value = loader.construct_sequence(node)
                    else:
                        value = loader.construct_scalar(node).split(".", 1)
                    if not isinstance(value, list) or len(value) != 2:
                        raise ValueError("!GetAtt must specify a resource and attribute")
                    return {"Fn::GetAtt": value}

                CloudFormationLoader.add_constructor(
                    "!Ref",
                    cloudformation_ref,
                )

                CloudFormationLoader.add_constructor(
                    "!GetAtt",
                    cloudformation_getatt,
                )

                raw_data = yaml.load(
                    text,
                    Loader=CloudFormationLoader,
                )
        except Exception as exc:
            raise ValueError(f"Invalid {extension} configuration: {exc}") from exc

        if is_cloudformation_template(raw_data):
            configuration = convert_cloudformation(raw_data)
            analysis_type = "CLOUDFORMATION"
        else:
            configuration = load_configuration(
                file_name,
                content,
            )
            analysis_type = "CLOUD_CONFIGURATION"

        findings_analysis = analyze_findings(
            configuration=configuration
        )

        graph = build_security_graph(configuration)
        attack_paths = find_attack_paths(graph)

        results = []

        for attack_path in attack_paths:
            path = attack_path["path"]

            risk = calculate_path_risk(graph, path)
            blast_radius = calculate_blast_radius(graph, path)
            alternate_paths = find_alternate_paths(graph, path)
            remediations = generate_remediations(graph, path)

            try:
                validation = validate_attack_path(graph, path)
            except Exception:
                validation = {
                    "status": "NOT_VALIDATED",
                    "reason": "Controlled validation unavailable",
                }

            results.append({
                "entry_point": attack_path["entry_point"],
                "target": attack_path["target"],
                "path": path,
                "length": attack_path["length"],
                "risk_score": risk["score"],
                "severity": risk["severity"],
                "risk_reasons": risk["reasons"],
                "blast_radius": blast_radius,
                "alternate_paths": alternate_paths,
                "remediations": remediations,
                "validation": validation,
            })

        optimized_remediations = optimize_remediations(
            graph,
            attack_paths,
        )

        persona_rankings = {}

        for persona_id in [
            "internet_opportunist",
            "privilege_escalator",
            "data_thief",
        ]:
            persona_rankings[persona_id] = rank_paths_by_persona(
                graph,
                attack_paths,
                persona_id,
            )

        risk_scores = [
            item["risk_score"]
            for item in results
        ]

        return {
            "analysis_type": analysis_type,
            "file_name": file_name,
            "configuration": configuration.model_dump(
                by_alias=True
            ),
            "summary": {
                "total_resources": len(configuration.resources),
                "critical_assets": sum(
                    1
                    for resource in configuration.resources
                    if resource.critical
                ),
                "dangerous_paths": len(results),
                "highest_risk": max(
                    risk_scores,
                    default=0,
                ),
                "total_findings": findings_analysis["summary"]["total_findings"],
                "critical_findings": findings_analysis["summary"]["critical_findings"],
                "high_findings": findings_analysis["summary"]["high_findings"],
            },
            "findings": findings_analysis["findings"],
            "findings_summary": findings_analysis["summary"],
            "attack_paths": results,
            "optimized_remediations": optimized_remediations,
            "persona_rankings": persona_rankings,
        }

    # Other explicitly supplied application/config files
    return analyze_uploaded_file(
        file_name=file_name,
        content=content,
    )
