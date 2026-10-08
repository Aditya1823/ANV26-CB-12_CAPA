from pathlib import Path
from typing import Dict, Any

from .analyze_findings import analyze_findings


SUPPORTED_TEXT_EXTENSIONS = {
    ".env",
    ".json",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".conf",
    ".properties",
    ".toml",
    ".txt",
}


def _get_file_type(file_name: str) -> str:
    name = Path(file_name).name.lower()

    if name == ".env" or name.startswith(".env."):
        return ".env"

    return Path(name).suffix.lower()


def analyze_uploaded_file(
    file_name: str,
    content: bytes,
) -> Dict[str, Any]:
    """
    Analyze an explicitly supplied project/application file.

    This function only analyzes file content explicitly provided
    by the caller. It does not scan the user's computer.
    """

    extension = _get_file_type(file_name)

    if extension not in SUPPORTED_TEXT_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type: {extension or '[no extension]'}. "
            f"Supported types: {sorted(SUPPORTED_TEXT_EXTENSIONS)}"
        )

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Uploaded file must be valid UTF-8 text") from exc

    result = analyze_findings(
        file_content=text,
        file_name=file_name,
    )

    return {
        "file_name": file_name,
        "file_type": extension or "text",
        "size_bytes": len(content),
        "analysis_type": "EXPLICIT_FILE_ANALYSIS",
        **result,
    }
