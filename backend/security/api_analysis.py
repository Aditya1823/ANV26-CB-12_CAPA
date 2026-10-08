from typing import Any, Dict

from .file_analyzer import analyze_uploaded_file


def analyze_explicit_file(
    file_name: str,
    content: bytes,
) -> Dict[str, Any]:
    return analyze_uploaded_file(
        file_name=file_name,
        content=content,
    )
