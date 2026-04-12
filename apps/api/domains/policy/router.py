from __future__ import annotations

import uuid

from fastapi import APIRouter, status

from api.core.auth import Auth

from .schemas import PolicyCreate, PolicyResponse, PolicyUpdate, ViolationResponse
from .service import create_policy, list_policies, list_violations, update_policy

router = APIRouter(prefix="/policies", tags=["policies"])


@router.get("", response_model=list[PolicyResponse])
async def list_policies_endpoint(auth: Auth):
    return await list_policies(auth.tenant_id)


@router.post("", response_model=PolicyResponse, status_code=status.HTTP_201_CREATED)
async def create_policy_endpoint(body: PolicyCreate, auth: Auth):
    auth.require_role("OWNER", "ADMIN")
    return await create_policy(auth.tenant_id, body, auth.user_id)


@router.patch("/{policy_id}", response_model=PolicyResponse)
async def update_policy_endpoint(policy_id: uuid.UUID, body: PolicyUpdate, auth: Auth):
    auth.require_role("OWNER", "ADMIN")
    return await update_policy(auth.tenant_id, policy_id, body)


@router.get("/violations", response_model=list[ViolationResponse])
async def list_violations_endpoint(policy_id: uuid.UUID | None = None, auth: Auth = None):
    return await list_violations(auth.tenant_id, policy_id)
