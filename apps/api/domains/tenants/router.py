from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from api.core.auth import Auth

from .schemas import TenantCreate, TenantResponse, TenantUpdate
from .service import create_tenant, get_tenant, update_tenant

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.post("", response_model=TenantResponse, status_code=status.HTTP_201_CREATED)
async def create_tenant_endpoint(body: TenantCreate, auth: Auth):
    auth.require_role("OWNER", "ADMIN")
    return await create_tenant(body)


@router.get("/me", response_model=TenantResponse)
async def get_my_tenant(auth: Auth):
    return await get_tenant(auth.tenant_id)


@router.patch("/me", response_model=TenantResponse)
async def update_my_tenant(body: TenantUpdate, auth: Auth):
    auth.require_role("OWNER", "ADMIN")
    return await update_tenant(auth.tenant_id, body)
