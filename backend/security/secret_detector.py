import re
from dataclasses import asdict, dataclass
from typing import List


@dataclass
class SecretFinding:
    finding_id: str
    type: str
    severity: str
    confidence: str
    file: str
    line: int
    key: str
    description: str
    evidence: str
    remediation: str


PATTERNS = [
    (
        "AWS_ACCESS_KEY",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "CRITICAL",
        "HIGH",
        "Potential AWS access key detected",
    ),
    (
        "PRIVATE_KEY",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
        "CRITICAL",
        "HIGH",
        "Private key material detected",
    ),
    (
        "JWT_TOKEN",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"
        ),
        "HIGH",
        "HIGH",
        "Potential JWT authentication token detected",
    ),
    (
        "GENERIC_SECRET",
        re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b"
            r"\s*[:=]\s*['\"]?([^\s'\"]{8,})"
        ),
        "HIGH",
        "MEDIUM",
        "Potential credential or secret value detected",
    ),
]


def detect_secrets(content: str, file_name: str = "uploaded_file") -> List[dict]:
    findings = []
    finding_number = 1

    for line_number, line in enumerate(content.splitlines(), start=1):
        for secret_type, pattern, severity, confidence, description in PATTERNS:
            match = pattern.search(line)

            if not match:
                continue

            key = match.group(1) if secret_type == "GENERIC_SECRET" else secret_type

            findings.append(
                asdict(
                    SecretFinding(
                        finding_id=f"SECRET-{finding_number:03d}",
                        type=secret_type,
                        severity=severity,
                        confidence=confidence,
                        file=file_name,
                        line=line_number,
                        key=key,
                        description=description,
                        evidence=f"{line[:120]}",
                        remediation=(
                            "Remove the secret from the supplied file, "
                            "revoke or rotate the exposed credential, "
                            "and store secrets in a secure secret manager."
                        ),
                    )
                )
            )

            finding_number += 1

    return findings
