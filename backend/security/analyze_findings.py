from typing import Optional

from models import CloudConfiguration

from .config_findings import detect_configuration_findings
from .findings import build_findings, summarize_findings
from .secret_detector import detect_secrets


def analyze_findings(
    configuration: Optional[CloudConfiguration] = None,
    file_content: Optional[str] = None,
    file_name: str = "uploaded_file",
) -> dict:
    configuration_findings = []

    if configuration is not None:
        configuration_findings = detect_configuration_findings(
            configuration
        )

    secret_findings = []

    if file_content is not None:
        secret_findings = detect_secrets(
            file_content,
            file_name,
        )

    findings = build_findings(
        configuration_findings=configuration_findings,
        secret_findings=secret_findings,
    )

    return {
        "findings": findings,
        "summary": summarize_findings(findings),
    }
