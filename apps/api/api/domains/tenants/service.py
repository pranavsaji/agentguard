from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

from api.core.database import get_engine, provision_tenant_schema
from api.core.events import publish_scan_requested

from .schemas import TenantCreate, TenantResponse, TenantUpdate


async def create_tenant(data: TenantCreate) -> TenantResponse:
    engine = get_engine()
    tenant_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    async with engine.begin() as conn:
        # Insert into global tenants table (public schema)
        await conn.execute(
            text("""
                INSERT INTO public.tenants (id, name, tier, deployment_mode, owner_email, created_at)
                VALUES (:id, :name, :tier, :deployment_mode, :owner_email, :created_at)
            """),
            {
                "id": str(tenant_id),
                "name": data.name,
                "tier": data.tier,
                "deployment_mode": data.deployment_mode,
                "owner_email": data.owner_email,
                "created_at": now,
            },
        )
        # Provision isolated schema + all tables for this tenant
        await provision_tenant_schema(tenant_id, conn)

    # Trigger initial scan for all providers
    await publish_scan_requested(tenant_id, ["AWS", "AZURE", "GCP", "GITHUB"])

    return TenantResponse(
        id=tenant_id,
        name=data.name,
        tier=data.tier,
        deployment_mode=data.deployment_mode,
        owner_email=data.owner_email,
        created_at=now,
    )


async def get_tenant(tenant_id: uuid.UUID) -> TenantResponse:
    engine = get_engine()
    async with engine.connect() as conn:
        row = await conn.execute(
            text("SELECT id, name, tier, deployment_mode, owner_email, created_at FROM public.tenants WHERE id = :id"),
            {"id": str(tenant_id)},
        )
        record = row.mappings().first()

    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")

    return TenantResponse(**dict(record))


async def update_tenant(tenant_id: uuid.UUID, data: TenantUpdate) -> TenantResponse:
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    if not updates:
        return await get_tenant(tenant_id)

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.execute(
            text(f"UPDATE public.tenants SET {set_clause} WHERE id = :id"),
            {**updates, "id": str(tenant_id)},
        )
    return await get_tenant(tenant_id)
