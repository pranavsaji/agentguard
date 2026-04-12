from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from api.core.auth import Auth

from .schemas import JITGrantRequest, JITGrantResponse
from .service import create_jit_grant, list_active_grants, revoke_jit_grant

router = APIRouter(prefix="/jit", tags=["jit"])


@router.post("/grants", response_model=JITGrantResponse, status_code=status.HTTP_201_CREATED)
async def issue_grant(body: JITGrantRequest, auth: Auth):
    auth.require_role("OWNER", "ADMIN")
    return await create_jit_grant(auth.tenant_id, body, auth.user_id)


@router.get("/grants", response_model=list[JITGrantResponse])
async def list_grants(auth: Auth):
    return await list_active_grants(auth.tenant_id)


@router.delete("/grants/{grant_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_grant(grant_id: uuid.UUID, auth: Auth):
    auth.require_role("OWNER", "ADMIN")
    await revoke_jit_grant(auth.tenant_id, grant_id, auth.user_id)
