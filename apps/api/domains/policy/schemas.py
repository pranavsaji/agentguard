from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class PolicyCreate(BaseModel):
    name: str
    description: str | None = None
    yaml_definition: str
    enforcement_mode: str = "MONITOR"
    compliance_mappings: list[str] = []


class PolicyResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None
    yaml_definition: str
    enforcement_mode: str
    enabled: bool
    compliance_mappings: list[str]
    created_by: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class PolicyUpdate(BaseModel):
    description: str | None = None
    yaml_definition: str | None = None
    enforcement_mode: str | None = None
    enabled: bool | None = None


class ViolationResponse(BaseModel):
    id: uuid.UUID
    nhi_id: uuid.UUID
    policy_id: uuid.UUID
    policy_name: str
    detected_at: datetime
    resolved_at: datetime | None
    resolution: str | None
    metadata: dict[str, Any]
