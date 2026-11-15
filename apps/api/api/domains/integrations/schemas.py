from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class WebhookType(str, Enum):
    SLACK = "SLACK"
    PAGERDUTY = "PAGERDUTY"
    GENERIC = "GENERIC"
    SPLUNK = "SPLUNK"
    DATADOG = "DATADOG"


class WebhookCreate(BaseModel):
    name: str
    url: str
    type: WebhookType
    secret: str | None = None
    events: list[str] = []  # e.g. ["POLICY_VIOLATION", "ANOMALY", "ROTATION_FAILED"]


class WebhookResponse(BaseModel):
    id: uuid.UUID
    name: str
    url: str
    type: str
    enabled: bool
    events: list[str]
    created_at: datetime
    last_triggered_at: datetime | None
    last_error: str | None


class AlertResponse(BaseModel):
    id: uuid.UUID
    type: str
    severity: str
    title: str
    description: str | None
    resource_type: str | None
    resource_id: str | None
    status: str
    created_at: datetime
