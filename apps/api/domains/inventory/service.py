from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import text

from api.core.database import tenant_session
from api.core.events import publish_rotation_requested, publish_scan_requested
from nhi_schema.models import NHIIdentity, NHIStatus, NHIType, Provider, ScanResult

from .schemas import NHIFilter, NHIListResponse, NHIResponse, NHIUpdate


async def upsert_identities(tenant_id: uuid.UUID, scan_result: ScanResult) -> int:
    """
    Persist a batch of NHI identities from a scan result. Uses INSERT … ON CONFLICT
    to update existing records without overwriting manually-set fields (owner_email, classification).
    Returns the number of rows upserted.
    """
    async with tenant_session(tenant_id) as session:
        count = 0
        for identity in scan_result.identities:
            await session.execute(
                text("""
                    INSERT INTO nhi_identities
                        (id, external_id, name, type, provider, classification,
                         owner_email, status, created_at, last_used_at, last_rotated_at,
                         last_scanned_at, raw_metadata)
                    VALUES
                        (:id, :external_id, :name, :type, :provider, :classification,
                         :owner_email, :status, :created_at, :last_used_at, :last_rotated_at,
                         NOW(), :raw_metadata)
                    ON CONFLICT (provider, external_id) DO UPDATE SET
                        name             = EXCLUDED.name,
                        status           = EXCLUDED.status,
                        last_used_at     = EXCLUDED.last_used_at,
                        last_rotated_at  = EXCLUDED.last_rotated_at,
                        last_scanned_at  = NOW(),
                        raw_metadata     = EXCLUDED.raw_metadata
                """),
                {
                    "id": str(identity.id),
                    "external_id": identity.external_id,
                    "name": identity.name,
                    "type": identity.type,
                    "provider": identity.provider,
                    "classification": identity.classification,
                    "owner_email": identity.owner_email,
                    "status": identity.status,
                    "created_at": identity.created_at,
                    "last_used_at": identity.last_used_at,
                    "last_rotated_at": identity.last_rotated_at,
                    "raw_metadata": identity.model_dump_json(include={"raw_metadata"}),
                },
            )
            count += 1
    return count


async def list_identities(tenant_id: uuid.UUID, filters: NHIFilter) -> NHIListResponse:
    conditions = ["1=1"]
    params: dict[str, Any] = {}

    if filters.provider:
        conditions.append("provider = :provider")
        params["provider"] = filters.provider
    if filters.type:
        conditions.append("type = :type")
        params["type"] = filters.type
    if filters.classification:
        conditions.append("classification = :classification")
        params["classification"] = filters.classification
    if filters.status:
        conditions.append("status = :status")
        params["status"] = filters.status
    if filters.owner_email:
        conditions.append("owner_email = :owner_email")
        params["owner_email"] = filters.owner_email

    where = " AND ".join(conditions)
    offset = (filters.page - 1) * filters.page_size

    async with tenant_session(tenant_id) as session:
        count_row = await session.execute(
            text(f"SELECT COUNT(*) FROM nhi_identities WHERE {where}"), params
        )
        total = count_row.scalar_one()

        rows = await session.execute(
            text(f"""
                SELECT n.*, rs.score, rs.severity, rs.factors, rs.computed_at AS score_computed_at
                FROM nhi_identities n
                LEFT JOIN LATERAL (
                    SELECT score, severity, factors, computed_at
                    FROM risk_scores
                    WHERE nhi_id = n.id
                    ORDER BY computed_at DESC LIMIT 1
                ) rs ON true
                WHERE {where}
                ORDER BY rs.score DESC NULLS LAST, n.last_scanned_at DESC
                LIMIT :limit OFFSET :offset
            """),
            {**params, "limit": filters.page_size, "offset": offset},
        )
        records = rows.mappings().all()

    items = [_row_to_response(r) for r in records]

    # Apply risk score filter after join (simpler than subquery)
    if filters.min_risk_score is not None:
        items = [i for i in items if i.risk_score and i.risk_score.score >= filters.min_risk_score]

    return NHIListResponse(items=items, total=total, page=filters.page, page_size=filters.page_size)


async def get_identity(tenant_id: uuid.UUID, nhi_id: uuid.UUID) -> NHIResponse:
    async with tenant_session(tenant_id) as session:
        row = await session.execute(
            text("""
                SELECT n.*, rs.score, rs.severity, rs.factors, rs.computed_at AS score_computed_at
                FROM nhi_identities n
                LEFT JOIN LATERAL (
                    SELECT score, severity, factors, computed_at
                    FROM risk_scores WHERE nhi_id = n.id
                    ORDER BY computed_at DESC LIMIT 1
                ) rs ON true
                WHERE n.id = :id
            """),
            {"id": str(nhi_id)},
        )
        record = row.mappings().first()

    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
    return _row_to_response(record)


async def update_identity(tenant_id: uuid.UUID, nhi_id: uuid.UUID, data: NHIUpdate) -> NHIResponse:
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    if not updates:
        return await get_identity(tenant_id, nhi_id)

    set_clause = ", ".join(f"{k} = :{k}" for k in updates)
    async with tenant_session(tenant_id) as session:
        result = await session.execute(
            text(f"UPDATE nhi_identities SET {set_clause} WHERE id = :id RETURNING id"),
            {**updates, "id": str(nhi_id)},
        )
        if not result.first():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")

    return await get_identity(tenant_id, nhi_id)


async def request_rotation(tenant_id: uuid.UUID, nhi_id: uuid.UUID, actor_id: str) -> None:
    await publish_rotation_requested(tenant_id, nhi_id, actor_id)


async def revoke_identity(tenant_id: uuid.UUID, nhi_id: uuid.UUID, reason: str, actor_id: str) -> None:
    async with tenant_session(tenant_id) as session:
        result = await session.execute(
            text("UPDATE nhi_identities SET status = 'REVOKED' WHERE id = :id RETURNING id"),
            {"id": str(nhi_id)},
        )
        if not result.first():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")
        # Append-only audit record
        await session.execute(
            text("""
                INSERT INTO audit_log (actor_type, actor_id, action, resource_type, resource_id, outcome, reason)
                VALUES ('USER', :actor_id, 'REVOKED_CREDENTIAL', 'NHIIdentity', :nhi_id, 'SUCCESS', :reason)
            """),
            {"actor_id": actor_id, "nhi_id": str(nhi_id), "reason": reason},
        )


async def trigger_scan(tenant_id: uuid.UUID, providers: list[str] | None) -> None:
    await publish_scan_requested(tenant_id, providers or ["AWS", "AZURE", "GCP", "GITHUB"])


def _row_to_response(r: Any) -> NHIResponse:
    import json
    from nhi_schema.models import RiskFactor, RiskScore

    risk_score = None
    if r.get("score") is not None:
        factors_raw = r["factors"]
        if isinstance(factors_raw, str):
            factors_raw = json.loads(factors_raw)
        risk_score = RiskScore(
            score=float(r["score"]),
            severity=r["severity"],
            computed_at=r["score_computed_at"],
            factors=[RiskFactor(**f) for f in (factors_raw or [])],
        )

    return NHIResponse(
        id=r["id"],
        external_id=r["external_id"],
        name=r["name"],
        type=r["type"],
        provider=r["provider"],
        classification=r.get("classification", "UNKNOWN"),
        owner_email=r.get("owner_email"),
        status=r.get("status", "ACTIVE"),
        created_at=r.get("created_at"),
        last_used_at=r.get("last_used_at"),
        last_rotated_at=r.get("last_rotated_at"),
        last_scanned_at=r["last_scanned_at"],
        risk_score=risk_score,
        raw_metadata=r.get("raw_metadata") or {},
    )
