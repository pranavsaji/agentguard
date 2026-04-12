from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from api.core.config import get_settings
from api.core.database import get_engine
from api.domains.behavioral.router import router as behavioral_router
from api.domains.compliance.router import router as compliance_router
from api.domains.integrations.router import router as integrations_router
from api.domains.inventory.router import router as inventory_router
from api.domains.jit.router import router as jit_router
from api.domains.policy.router import router as policy_router
from api.domains.risk.router import router as risk_router
from api.domains.tenants.router import router as tenants_router
from nhi_schema.models import ScanResult


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure global tenants table exists on startup
    engine = get_engine()
    async with engine.begin() as conn:
        from sqlalchemy import text
        await conn.execute(text("""
            CREATE TABLE IF NOT EXISTS public.tenants (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                name TEXT NOT NULL,
                tier TEXT NOT NULL DEFAULT 'starter',
                deployment_mode TEXT NOT NULL DEFAULT 'saas',
                owner_email TEXT NOT NULL,
                kms_key_id TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW()
            )
        """))
    yield
    await engine.dispose()


cfg = get_settings()

app = FastAPI(
    title=cfg.app_name,
    version="0.1.0",
    docs_url="/docs" if cfg.debug else None,
    redoc_url="/redoc" if cfg.debug else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.agentguard.io", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error"},
    )


# Mount domain routers
prefix = cfg.api_v1_prefix
app.include_router(tenants_router, prefix=prefix)
app.include_router(inventory_router, prefix=prefix)
app.include_router(policy_router, prefix=prefix)
app.include_router(jit_router, prefix=prefix)
app.include_router(risk_router, prefix=prefix)
app.include_router(behavioral_router, prefix=prefix)
app.include_router(compliance_router, prefix=prefix)
app.include_router(integrations_router, prefix=prefix)


async def _verify_sensor_token(x_sensor_token: Annotated[str | None, Header()] = None) -> None:
    """Dependency: validates the sensor's shared-secret token (not a Clerk JWT)."""
    cfg = get_settings()
    if not cfg.sensor_auth_secret:
        return  # Skip auth in dev when secret is not configured
    if x_sensor_token != cfg.sensor_auth_secret:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sensor token")


@app.post("/v1/internal/scan-results", status_code=status.HTTP_202_ACCEPTED, include_in_schema=False)
async def ingest_scan_results(
    payload: ScanResult,
    _: Annotated[None, __import__("fastapi").Depends(_verify_sensor_token)],
):
    """
    Internal endpoint: sensor POSTs normalized NHI scan results here.
    Persists identities, then queues async risk recomputation + policy evaluation.
    Not exposed in public OpenAPI docs.
    """
    from api.core.events import publish_scan_requested
    from api.domains.inventory.service import upsert_identities

    count = await upsert_identities(payload.tenant_id, payload)
    # Queue risk recomputation for the affected tenant
    await publish_scan_requested(payload.tenant_id, [payload.provider])
    return {"accepted": count, "tenant_id": str(payload.tenant_id)}


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
