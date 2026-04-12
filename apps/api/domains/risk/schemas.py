from __future__ import annotations

from typing import Any
import uuid
from datetime import datetime

from pydantic import BaseModel


class RiskStatsResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    unscored: int
    avg_score: float


class RiskHistoryEntry(BaseModel):
    id: uuid.UUID
    score: float
    severity: str
    factors: list[dict[str, Any]]
    computed_at: datetime


class TopRiskyIdentity(BaseModel):
    id: uuid.UUID
    name: str
    provider: str
    type: str
    score: float
    severity: str
    top_factor: str | None
    top_remediation: str | None
