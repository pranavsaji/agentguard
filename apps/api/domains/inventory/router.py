from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from api.core.auth import Auth

from .schemas import (
    NHIFilter,
    NHIListResponse,
    NHIResponse,
    NHIUpdate,
    RevokeRequest,
    RotateRequest,
    ScanRequest,
)
from .service import (
    get_identity,
    list_identities,
    request_rotation,
    revoke_identity,
    trigger_scan,
    update_identity,
)

router = APIRouter(prefix="/identities", tags=["identities"])


@router.get("", response_model=NHIListResponse)
async def list_nhi(filters: NHIFilter = NHIFilter(), auth: Auth = None):
    return await list_identities(auth.tenant_id, filters)


@router.get("/{nhi_id}", response_model=NHIResponse)
async def get_nhi(nhi_id: uuid.UUID, auth: Auth = None):
    return await get_identity(auth.tenant_id, nhi_id)


@router.patch("/{nhi_id}", response_model=NHIResponse)
async def update_nhi(nhi_id: uuid.UUID, body: NHIUpdate, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN", "ANALYST")
    return await update_identity(auth.tenant_id, nhi_id, body)


@router.post("/{nhi_id}/rotate", status_code=status.HTTP_202_ACCEPTED)
async def rotate_nhi(nhi_id: uuid.UUID, body: RotateRequest, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN")
    await request_rotation(auth.tenant_id, nhi_id, auth.user_id)
    return {"message": "Rotation queued", "nhi_id": str(nhi_id)}


@router.post("/{nhi_id}/revoke", status_code=status.HTTP_200_OK)
async def revoke_nhi(nhi_id: uuid.UUID, body: RevokeRequest, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN")
    await revoke_identity(auth.tenant_id, nhi_id, body.reason, auth.user_id)
    return {"message": "Identity revoked", "nhi_id": str(nhi_id)}


@router.post("/scans", status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan_endpoint(body: ScanRequest, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN")
    providers = [p.value for p in body.providers] if body.providers else None
    await trigger_scan(auth.tenant_id, providers)
    return {"message": "Scan queued", "providers": providers or "all"}
