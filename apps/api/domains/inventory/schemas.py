from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from nhi_schema.models import Classification, NHIStatus, NHIType, Permission, Provider, RiskScore


class NHIResponse(BaseModel):
    id: uuid.UUID
    external_id: str
    name: str
    type: NHIType
    provider: Provider
    classification: Classification
    owner_email: str | None
    status: NHIStatus
    created_at: datetime | None
    last_used_at: datetime | None
    last_rotated_at: datetime | None
    last_scanned_at: datetime
    risk_score: RiskScore | None
    raw_metadata: dict[str, Any]

    model_config = {"from_attributes": True}


class NHIListResponse(BaseModel):
    items: list[NHIResponse]
    total: int
    page: int
    page_size: int


class NHIFilter(BaseModel):
    provider: Provider | None = None
    type: NHIType | None = None
    classification: Classification | None = None
    status: NHIStatus | None = None
    min_risk_score: float | None = None
    owner_email: str | None = None
    page: int = 1
    page_size: int = 50


class NHIUpdate(BaseModel):
    owner_email: str | None = None
    classification: Classification | None = None


class RotateRequest(BaseModel):
    reason: str = "Manual rotation requested"


class RevokeRequest(BaseModel):
    reason: str


class ScanRequest(BaseModel):
    providers: list[Provider] | None = None  # None means all connected providers
