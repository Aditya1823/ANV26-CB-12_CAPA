from typing import Any, Dict, List, Set
import re

from models import CloudConfiguration


def _logical_refs(value: Any) -> Set[str]:
    refs: Set[str] = set()

    if isinstance(value, dict):
        if "Ref" in value and isinstance(value["Ref"], str):
            refs.add(value["Ref"])

        if "Fn::GetAtt" in value:
            get_att = value["Fn::GetAtt"]
            if isinstance(get_att, list) and get_att:
                if isinstance(get_att[0], str):
                    refs.add(get_att[0])
            elif isinstance(get_att, str):
                refs.add(get_att.split(".", 1)[0])

        for nested in value.values():
            refs.update(_logical_refs(nested))

    elif isinstance(value, list):
        for item in value:
            refs.update(_logical_refs(item))

    elif isinstance(value, str):
        # Detect CloudFormation references embedded in Fn::Sub strings,
        # e.g. ${CustomerDatabase.Endpoint.Address}
        refs.update(
            match.group(1)
            for match in re.finditer(
                r"\$\{([A-Za-z0-9]+)(?:\.[^}]+)?\}",
                value,
            )
        )

    return refs


def _policy_is_admin(policy: Any) -> bool:
    text = str(policy).lower()

    return (
        "administratoraccess" in text
        or '"action": "*"' in text
        or "'action': '*'" in text
        or '"resource": "*"' in text
        or "'resource': '*'" in text
    )


def _security_group_is_public(properties: Dict[str, Any]) -> bool:
    permissions = properties.get("SecurityGroupIngress", [])
    if not isinstance(permissions, list):
        return False

    for rule in permissions:
        if not isinstance(rule, dict):
            continue

        cidr = rule.get("CidrIp")
        cidrs = rule.get("CidrIps", [])

        if cidr == "0.0.0.0/0":
            return True

        if isinstance(cidrs, list) and "0.0.0.0/0" in cidrs:
            return True

    return False


def _resource_metadata(logical_id: str, resource: Dict[str, Any]) -> Dict[str, Any]:
    resource_type = resource.get("Type", "")
    properties = resource.get("Properties", {}) or {}

    # Some generated CloudFormation templates may use an intrinsic
    # function where a resource type string is expected. Normalize it
    # safely instead of crashing the entire analysis.
    if not isinstance(resource_type, str):
        resource_type = "UNKNOWN"

    metadata = {
        "id": logical_id,
        "type": resource_type,
        "internet_exposed": False,
        "critical": False,
        "excessive_permission": False,
        "admin_permission": False,
        "public_access": False,
        "sensitivity": "normal",
    }

    # IAM
    if resource_type == "AWS::IAM::Role":
        metadata["type"] = "IAM_ROLE"

        policies = properties.get("Policies", [])
        managed = properties.get("ManagedPolicyArns", [])

        if _policy_is_admin(policies) or _policy_is_admin(managed):
            metadata["admin_permission"] = True
            metadata["excessive_permission"] = True
        elif policies or managed:
            metadata["excessive_permission"] = True

    # EC2
    elif resource_type == "AWS::EC2::Instance":
        metadata["type"] = "SERVER"

    # Security Group
    elif resource_type == "AWS::EC2::SecurityGroup":
        metadata["type"] = "SECURITY_GROUP"

        if _security_group_is_public(properties):
            metadata["public_access"] = True
            metadata["internet_exposed"] = True

    # S3
    elif resource_type == "AWS::S3::Bucket":
        metadata["type"] = "STORAGE"
        metadata["critical"] = True
        metadata["sensitivity"] = "high"

        public_access_block = properties.get("PublicAccessBlockConfiguration", {})
        if isinstance(public_access_block, dict):
            if public_access_block.get("BlockPublicPolicy") is False:
                metadata["public_access"] = True
            if public_access_block.get("RestrictPublicBuckets") is False:
                metadata["public_access"] = True

    # RDS
    elif resource_type in {
        "AWS::RDS::DBInstance",
        "AWS::RDS::DBCluster",
    }:
        metadata["type"] = "DATABASE"
        metadata["critical"] = True
        metadata["sensitivity"] = "high"

        if properties.get("PubliclyAccessible") is True:
            metadata["internet_exposed"] = True
            metadata["public_access"] = True

    # Lambda
    elif resource_type == "AWS::Lambda::Function":
        metadata["type"] = "FUNCTION"

    # API Gateway
    elif resource_type.startswith("AWS::ApiGateway"):
        metadata["type"] = "API"
        metadata["internet_exposed"] = True

    # ALB / ELB
    elif resource_type in {
        "AWS::ElasticLoadBalancingV2::LoadBalancer",
        "AWS::ElasticLoadBalancing::LoadBalancer",
    }:
        metadata["type"] = "LOAD_BALANCER"

        if properties.get("Scheme") == "internet-facing":
            metadata["internet_exposed"] = True

    # CloudFront
    elif resource_type == "AWS::CloudFront::Distribution":
        metadata["type"] = "CDN"
        metadata["internet_exposed"] = True

    return metadata


def is_cloudformation_template(data: Dict[str, Any]) -> bool:
    if not isinstance(data, dict):
        return False

    resources = data.get("Resources")

    if not isinstance(resources, dict):
        return False

    return (
        "AWSTemplateFormatVersion" in data
        or "Transform" in data
        or any(
            isinstance(resource, dict)
            and isinstance(resource.get("Type"), str)
            and resource["Type"].startswith("AWS::")
            for resource in resources.values()
        )
    )


def convert_cloudformation(data: Dict[str, Any]) -> CloudConfiguration:
    resources_data = data.get("Resources", {})

    if not isinstance(resources_data, dict):
        raise ValueError("CloudFormation template must contain a Resources object")

    resources: List[Dict[str, Any]] = []
    connections: List[Dict[str, Any]] = []

    logical_ids = set(resources_data.keys())

    for logical_id, resource in resources_data.items():
        if not isinstance(resource, dict):
            continue

        metadata = _resource_metadata(logical_id, resource)
        resources.append(metadata)

    # Propagate public Security Group exposure to resources attached to it.
    public_security_groups = {
        resource_id
        for resource_id, resource in resources_data.items()
        if isinstance(resource, dict)
        and _resource_metadata(resource_id, resource)["type"] == "SECURITY_GROUP"
        and _resource_metadata(resource_id, resource)["internet_exposed"]
    }

    for metadata in resources:
        resource_id = metadata["id"]
        resource = resources_data.get(resource_id, {})
        properties = resource.get("Properties", {}) if isinstance(resource, dict) else {}

        attached_groups = set()

        for key in ("SecurityGroupIds", "SecurityGroups"):
            value = properties.get(key, [])
            if isinstance(value, list):
                attached_groups.update(_logical_refs(value))
            else:
                attached_groups.update(_logical_refs(value))

        if attached_groups & public_security_groups:
            metadata["internet_exposed"] = True

    for logical_id, resource in resources_data.items():
        if not isinstance(resource, dict):
            continue

        properties = resource.get("Properties", {}) or {}
        refs = _logical_refs(properties)

        # Infer common AWS application relationships that CloudFormation
        # expresses through nested properties rather than direct Ref links.
        resource_type = resource.get("Type", "")

        if resource_type == "AWS::EC2::Instance":
            # An EC2 instance using an IAM instance profile is associated
            # with the corresponding IAM role/profile.
            profile = properties.get("IamInstanceProfile")
            refs.update(_logical_refs(profile))

            # UserData may reference databases, queues, buckets, etc.
            user_data = properties.get("UserData")
            refs.update(_logical_refs(user_data))

        if resource_type == "AWS::Lambda::Function":
            role = properties.get("Role")
            refs.update(_logical_refs(role))

            environment = properties.get("Environment", {})
            refs.update(_logical_refs(environment))

        if resource_type == "AWS::RDS::DBInstance":
            subnet_group = properties.get("DBSubnetGroupName")
            refs.update(_logical_refs(subnet_group))

        depends_on = resource.get("DependsOn", [])
        if isinstance(depends_on, str):
            refs.add(depends_on)
        elif isinstance(depends_on, list):
            refs.update(
                item for item in depends_on
                if isinstance(item, str)
            )

        refs &= logical_ids
        refs.discard(logical_id)

        source_meta = _resource_metadata(logical_id, resource)

        for target_id in sorted(refs):
            target_meta = _resource_metadata(
                target_id,
                resources_data[target_id],
            )

            dangerous = (
                source_meta["internet_exposed"]
                or source_meta["admin_permission"]
                or source_meta["excessive_permission"]
                or source_meta["public_access"]
            )

            permission = None

            if source_meta["type"] == "IAM_ROLE":
                permission = "TRUST"
            elif target_meta["type"] == "DATABASE":
                permission = "READ_WRITE"
            elif target_meta["type"] == "STORAGE":
                permission = "READ"

            connections.append({
                "from": logical_id,
                "to": target_id,
                "type": "cloudformation_reference",
                "permission": permission,
                "dangerous": dangerous,
            })

    if not resources:
        raise ValueError("CloudFormation template contains no supported resources")

    return CloudConfiguration(
        resources=resources,
        connections=connections,
    )
