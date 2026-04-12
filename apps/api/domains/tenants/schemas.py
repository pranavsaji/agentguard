from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, EmailStr


class TenantCreate(BaseModel):
    name: str
    owner_email: EmailStr
    tier: str = "starter"          # starter | professional | enterprise | onprem
    deployment_mode: str = "saas"  # saas | hybrid


class TenantResponse(BaseModel):
    id: uuid.UUID
    name: str
    tier: str
    deployment_mode: str
    owner_email: str
    created_at: datetime

    model_config = {"from_attributes": True}


class TenantUpdate(BaseModel):
    name: str | None = None
    tier: str | None = None
