from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class BehavioralEventCreate(BaseModel):
    nhi_id: uuid.UUID
    event_type: str  # API_CALL | AUTH_SUCCESS | AUTH_FAILURE | DATA_ACCESS | ADMIN_ACTION
    service: str | None = None
    region: str | None = None
    ip_address: str | None = None
    bytes_transferred: int = 0
    success: bool = True
    occurred_at: datetime | None = None  # defaults to now if omitted
    metadata: dict = {}


class BehavioralEventResponse(BaseModel):
    id: uuid.UUID
    nhi_id: uuid.UUID
    event_type: str
    service: str | None
    region: str | None
    success: bool
    occurred_at: datetime


class AnomalyFlag(BaseModel):
    nhi_id: uuid.UUID
    nhi_name: str
    anomaly_score: float  # 0-1, higher = more anomalous
    signals: list[str]  # human-readable explanations


class BaselineStatus(BaseModel):
    nhi_id: uuid.UUID
    warmup_complete: bool
    computed_at: datetime | None
    event_count_14d: int
