from typing import List, Optional

from pydantic import BaseModel, Field


# ============================================================
# CLOUD RESOURCE
# ============================================================

class Resource(BaseModel):
    id: str
    type: str

    internet_exposed: bool = False
    critical: bool = False

    excessive_permission: bool = False
    admin_permission: bool = False
    public_access: bool = False

    sensitivity: str = "normal"


# ============================================================
# CLOUD CONNECTION
# ============================================================

class Connection(BaseModel):
    source: str = Field(alias="from")
    target: str = Field(alias="to")

    type: str

    permission: Optional[str] = None
    dangerous: bool = False


# ============================================================
# CLOUD CONFIGURATION
# ============================================================

class CloudConfiguration(BaseModel):
    resources: List[Resource]
    connections: List[Connection]


# ============================================================
# SINGLE REMEDIATION ACTION
# ============================================================

class RemediationAction(BaseModel):
    action: str
    resource: str
    target: Optional[str] = None


# ============================================================
# ANALYSIS REQUEST
# ============================================================

class AnalyzeRequest(BaseModel):
    configuration: CloudConfiguration


# ============================================================
# SINGLE-FIX SIMULATION REQUEST
# ============================================================

class SimulateRemediationRequest(BaseModel):
    configuration: CloudConfiguration
    remediation: RemediationAction


# ============================================================
# MULTI-FIX SIMULATION REQUEST
# ============================================================

class SimulateRemediationSetRequest(BaseModel):
    configuration: CloudConfiguration
    remediations: List[RemediationAction]