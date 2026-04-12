from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import text

from api.core.database import tenant_session

from .schemas import JITGrantRequest, JITGrantResponse


async def create_jit_grant(
    tenant_id: uuid.UUID,
    data: JITGrantRequest,
    actor_id: str,
) -> JITGrantResponse:
    grant_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=data.ttl_minutes)

    async with tenant_session(tenant_id) as session:
        # Verify NHI exists and is ACTIVE
        row = await session.execute(
            text("SELECT id, status FROM nhi_identities WHERE id = :id"),
            {"id": str(data.nhi_id)},
        )
        record = row.mappings().first()
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
        if record["status"] != "ACTIVE":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Cannot issue JIT grant for identity in status '{record['status']}'",
            )

        import json
        await session.execute(
            text("""
                INSERT INTO jit_grants
                    (id, requester_id, nhi_id, scope, reason, approved_by, issued_at, expires_at, status)
                VALUES
                    (:id, :requester_id, :nhi_id, :scope, :reason, :approved_by, :issued_at, :expires_at, 'ACTIVE')
            """),
            {
                "id": str(grant_id),
                "requester_id": actor_id,
                "nhi_id": str(data.nhi_id),
                "scope": json.dumps(data.scope),
                "reason": data.reason,
                "approved_by": actor_id,
                "issued_at": now,
                "expires_at": expires_at,
            },
        )
        # Audit trail
        await session.execute(
            text("""
                INSERT INTO audit_log
                    (actor_type, actor_id, action, resource_type, resource_id, outcome, reason)
                VALUES ('USER', :actor_id, 'JIT_GRANT_ISSUED', 'JITGrant', :grant_id, 'SUCCESS', :reason)
            """),
            {"actor_id": actor_id, "grant_id": str(grant_id), "reason": data.reason},
        )

    return JITGrantResponse(
        id=grant_id,
        nhi_id=data.nhi_id,
        scope=data.scope,
        reason=data.reason,
        approved_by=actor_id,
        issued_at=now,
        expires_at=expires_at,
        status="ACTIVE",
        credential_hint=f"Vault path: agentguard/jit/{grant_id}",
    )


async def list_active_grants(tenant_id: uuid.UUID) -> list[JITGrantResponse]:
    import json
    async with tenant_session(tenant_id) as session:
        rows = await session.execute(
            text("""
                SELECT * FROM jit_grants
                WHERE status = 'ACTIVE' AND expires_at > NOW()
                ORDER BY issued_at DESC
            """)
        )
        return [
            JITGrantResponse(
                **{**dict(r), "scope": json.loads(r["scope"]) if isinstance(r["scope"], str) else r["scope"]}
            )
            for r in rows.mappings()
        ]


async def revoke_jit_grant(tenant_id: uuid.UUID, grant_id: uuid.UUID, actor_id: str) -> None:
    async with tenant_session(tenant_id) as session:
        result = await session.execute(
            text("""
                UPDATE jit_grants
                SET status = 'REVOKED', revoked_at = NOW()
                WHERE id = :id AND status = 'ACTIVE'
                RETURNING id
            """),
            {"id": str(grant_id)},
        )
        if not result.first():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Active grant not found")
        await session.execute(
            text("""
                INSERT INTO audit_log
                    (actor_type, actor_id, action, resource_type, resource_id, outcome, reason)
                VALUES ('USER', :actor_id, 'JIT_GRANT_REVOKED', 'JITGrant', :grant_id, 'SUCCESS', 'Manual revocation')
            """),
            {"actor_id": actor_id, "grant_id": str(grant_id)},
        )
