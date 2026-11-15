from __future__ import annotations

import uuid

from fastapi import APIRouter, Header, HTTPException, Query, status

from api.core.auth import Auth
from api.core.config import get_settings

from .schemas import (
    AnomalyFlag,
    BaselineStatus,
    BehavioralEventCreate,
    BehavioralEventResponse,
)
from .service import compute_baseline, get_anomalies, get_timeline, ingest_events

router = APIRouter(prefix="/behavioral", tags=["behavioral"])


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def ingest_behavioral_events(
    body: list[BehavioralEventCreate],
    x_sensor_token: str | None = Header(None),
    x_tenant_id: str | None = Header(None),
):
    """
    Sensor push endpoint — uses shared-secret auth, not Clerk JWTs.
    Requires X-Tenant-Id header to identify the tenant.
    """
    cfg = get_settings()
    if cfg.sensor_auth_secret and x_sensor_token != cfg.sensor_auth_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sensor token"
        )
    if not x_tenant_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="X-Tenant-Id header required"
        )
    try:
        tenant_id = uuid.UUID(x_tenant_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid tenant ID format"
        )

    count = await ingest_events(tenant_id, body)
    return {"accepted": count}


@router.get("/{nhi_id}/timeline", response_model=list[BehavioralEventResponse])
async def behavioral_timeline(
    nhi_id: uuid.UUID,
    hours: int = Query(default=24, ge=1, le=720),
    auth: Auth = None,
):
    return await get_timeline(auth.tenant_id, nhi_id, hours=hours)


@router.get("/anomalies", response_model=list[AnomalyFlag])
async def behavioral_anomalies(auth: Auth = None):
    return await get_anomalies(auth.tenant_id)


@router.post("/{nhi_id}/baseline", response_model=BaselineStatus)
async def baseline_nhi(nhi_id: uuid.UUID, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN")
    return await compute_baseline(auth.tenant_id, nhi_id)
