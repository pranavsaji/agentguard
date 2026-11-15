from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, status

from api.core.auth import Auth

from .schemas import RiskHistoryEntry, RiskStatsResponse, TopRiskyIdentity
from .service import get_risk_history, get_risk_stats, get_top_risky, recompute_all

router = APIRouter(prefix="/risk", tags=["risk"])


@router.get("/stats", response_model=RiskStatsResponse)
async def risk_stats(auth: Auth = None):
    return await get_risk_stats(auth.tenant_id)


@router.get("/top", response_model=list[TopRiskyIdentity])
async def top_risky(limit: int = Query(default=20, ge=1, le=100), auth: Auth = None):
    return await get_top_risky(auth.tenant_id, limit=limit)


@router.get("/{nhi_id}/history", response_model=list[RiskHistoryEntry])
async def risk_history(
    nhi_id: uuid.UUID,
    limit: int = Query(default=30, ge=1, le=200),
    auth: Auth = None,
):
    return await get_risk_history(auth.tenant_id, nhi_id, limit=limit)


@router.post("/recompute", status_code=status.HTTP_202_ACCEPTED)
async def recompute(auth: Auth = None):
    auth.require_role("OWNER", "ADMIN")
    count = await recompute_all(auth.tenant_id)
    return {"message": "Risk recomputation complete", "scored": count}
