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
    ("AWS_ACCESS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "CRITICAL", "HIGH", "Potential AWS access key detected"),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "CRITICAL", "HIGH", "Private key material detected"),
    ("JWT_TOKEN", re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "HIGH", "HIGH", "Potential JWT authentication token detected"),
    ("HIDDEN_HTML_SECRET", re.compile(r"""(?is)<input\b(?=[^>]*\btype\s*=\s*["']?hidden\b)(?=[^>]*\bvalue\s*=\s*["'][^"']{8,}["'])[^>]*>"""), "HIGH", "MEDIUM", "Potential secret stored in a hidden HTML input"),
    ("API_KEY_ASSIGNMENT", re.compile(r"""(?i)\bAPI[_-]?KEY\b\s*[:=]\s*["']?([^\s"'<>;,}]{8,})"""), "HIGH", "HIGH", "Potential API key assignment detected"),
    ("HTML_DATA_SECRET", re.compile(r"""(?i)\bdata-secret\s*=\s*["']([^"']{8,})["']"""), "HIGH", "HIGH", "Potential secret stored in an HTML data attribute"),
    ("GENERIC_SECRET", re.compile(r"""(?i)\b([A-Za-z_$][\w$-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|token)[\w$-]*)\b\s*[:=]\s*["']?([^\s"'<>;,}]{8,})"""), "HIGH", "MEDIUM", "Potential credential or secret value detected"),
]


def detect_secrets(content: str, file_name: str = "uploaded_file") -> List[dict]:
    findings = []
    seen = set()

    for line_number, line in enumerate(content.splitlines(), start=1):
        for secret_type, pattern, severity, confidence, description in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue

            # Avoid reporting a generic match when a dedicated detector
            # already identifies the same HTML attribute or API key.
            if secret_type == "GENERIC_SECRET" and any(
                item["line"] == line_number
                and item["type"] in {"API_KEY_ASSIGNMENT", "HTML_DATA_SECRET"}
                for item in findings
            ):
                continue

            key = match.group(1) if secret_type == "GENERIC_SECRET" else secret_type
            identity = (secret_type, line_number, key)
            if identity in seen:
                continue
            seen.add(identity)

            findings.append(asdict(SecretFinding(
                finding_id=f"SECRET-{len(findings) + 1:03d}",
                type=secret_type,
                severity=severity,
                confidence=confidence,
                file=file_name,
                line=line_number,
                key=key,
                description=description,
                evidence="Sensitive value redacted; inspect the file locally at the reported line.",
                remediation="Remove the secret from the supplied file, revoke or rotate the exposed credential, and store secrets in a secure secret manager.",
            )))

    return findings
