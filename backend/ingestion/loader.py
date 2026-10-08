import json
from pathlib import Path

import yaml

from models import CloudConfiguration


SUPPORTED_EXTENSIONS = {".json", ".yaml", ".yml"}


def load_configuration(file_name: str, content: bytes) -> CloudConfiguration:
    """
    Safely parse an explicitly supplied JSON/YAML configuration file
    into the existing CloudConfiguration model.
    """

    extension = Path(file_name).suffix.lower()

    if extension not in SUPPORTED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type: {extension}. "
            f"Supported types: {sorted(SUPPORTED_EXTENSIONS)}"
        )

    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("Configuration file must be valid UTF-8 text") from exc

    try:
        if extension == ".json":
            data = json.loads(text)
        else:
            data = yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"Invalid {extension} configuration: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Configuration root must be an object")

    if "configuration" in data:
        data = data["configuration"]

    if not isinstance(data, dict):
        raise ValueError("Configuration must be an object")

    if "resources" not in data:
        raise ValueError("Configuration must contain 'resources'")

    if "connections" not in data:
        raise ValueError("Configuration must contain 'connections'")

    return CloudConfiguration(**data)
