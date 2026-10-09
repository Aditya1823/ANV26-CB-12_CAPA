import json
from pathlib import Path

import yaml

class CloudFormationLoader(yaml.SafeLoader):
    pass

def _cloudformation_tag(loader, tag_suffix, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node, deep=True)
    else:
        value = loader.construct_mapping(node, deep=True)

    tag = tag_suffix

    if tag == "Ref":
        return {"Ref": value}

    if tag == "GetAtt":
        if isinstance(value, str):
            value = value.split(".", 1)
        return {"Fn::GetAtt": value}

    return {"Fn::" + tag: value}

CloudFormationLoader.add_multi_constructor("!", _cloudformation_tag)
yaml.SafeLoader.add_multi_constructor("!", _cloudformation_tag)

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
            data = yaml.load(text, Loader=CloudFormationLoader)
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
