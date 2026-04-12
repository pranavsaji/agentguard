"""
Canonical NHI (Non-Human Identity) data model shared across api, sensor, and web packages.
All cloud connectors normalize their output to these types.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class NHIType(str, Enum):
    API_KEY = "API_KEY"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    OAUTH_TOKEN = "OAUTH_TOKEN"
    BOT = "BOT"
    AGENT_CREDENTIAL = "AGENT_CREDENTIAL"


class Provider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    GITHUB = "GITHUB"
    GITLAB = "GITLAB"


class Classification(str, Enum):
    AI_AGENT = "AI_AGENT"
    CICD = "CICD"
    INTEGRATION = "INTEGRATION"
    HUMAN_PROXY = "HUMAN_PROXY"
    UNKNOWN = "UNKNOWN"


class NHIStatus(str, Enum):
    ACTIVE = "ACTIVE"
    STALE = "STALE"
    ORPHANED = "ORPHANED"
    REVOKED = "REVOKED"


class Permission(BaseModel):
    action: str
    resource: str
    effect: str = "Allow"
    condition: dict[str, Any] | None = None


class RiskFactor(BaseModel):
    name: str
    weight: float
    raw_value: float
    contribution: float
    remediation: str | None = None


class RiskScore(BaseModel):
    score: float = Field(ge=0, le=100)
    factors: list[RiskFactor]
    computed_at: datetime
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL

    @classmethod
    def severity_from_score(cls, score: float) -> str:
        if score < 25:
            return "LOW"
        if score < 50:
            return "MEDIUM"
        if score < 75:
            return "HIGH"
        return "CRITICAL"


class NHIIdentity(BaseModel):
    """Canonical representation of any non-human identity, provider-agnostic."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: uuid.UUID
    external_id: str
    name: str
    type: NHIType
    provider: Provider
    classification: Classification = Classification.UNKNOWN
    owner_email: str | None = None
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    last_rotated_at: datetime | None = None
    last_scanned_at: datetime = Field(default_factory=datetime.utcnow)
    permissions: list[Permission] = Field(default_factory=list)
    risk_score: RiskScore | None = None
    status: NHIStatus = NHIStatus.ACTIVE
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class ScanResult(BaseModel):
    """Output of a single connector scan run."""

    provider: Provider
    tenant_id: uuid.UUID
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    identities: list[NHIIdentity]
    error: str | None = None
    duration_seconds: float | None = None


class PolicyRule(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    name: str
    description: str | None = None
    yaml_definition: str
    enforcement_mode: str = "MONITOR"  # MONITOR | ALERT | ENFORCE | AUTO_REMEDIATE
    enabled: bool = True
    compliance_mappings: list[str] = Field(default_factory=list)


class PolicyViolation(BaseModel):
    nhi_id: uuid.UUID
    policy_id: uuid.UUID
    detected_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class AuditEvent(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    tenant_id: uuid.UUID
    actor_type: str  # USER | SENSOR | POLICY | SYSTEM
    actor_id: str
    action: str
    resource_type: str | None = None
    resource_id: str | None = None
    outcome: str  # SUCCESS | FAILURE
    reason: str | None = None
    ip_address: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class JITGrant(BaseModel):
    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    requester_id: str
    nhi_id: uuid.UUID
    scope: dict[str, Any]
    reason: str
    approved_by: str | None = None
    issued_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime
    revoked_at: datetime | None = None
    status: str = "ACTIVE"
