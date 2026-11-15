from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel


class JITGrantRequest(BaseModel):
    nhi_id: uuid.UUID
    scope: dict[str, Any]          # e.g. {"actions": ["s3:GetObject"], "resources": ["arn:..."]}
    reason: str
    ttl_minutes: int = 60          # Default 1-hour credential lifetime


class JITGrantResponse(BaseModel):
    id: uuid.UUID
    nhi_id: uuid.UUID
    scope: dict[str, Any]
    reason: str
    approved_by: str | None
    issued_at: datetime
    expires_at: datetime
    status: str
    credential_hint: str | None = None   # e.g. "Check Vault path: agentguard/jit/{id}"
