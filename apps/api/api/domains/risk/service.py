from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import text

from api.core.database import tenant_session

from .schemas import RiskHistoryEntry, RiskStatsResponse, TopRiskyIdentity


async def get_risk_stats(tenant_id: uuid.UUID) -> RiskStatsResponse:
    async with tenant_session(tenant_id) as session:
        # Count scored NHIs by severity + avg score
        rows = await session.execute(
            text("""
                SELECT
                    COUNT(*) AS total_scored,
                    COUNT(*) FILTER (WHERE rs.severity = 'CRITICAL') AS critical,
                    COUNT(*) FILTER (WHERE rs.severity = 'HIGH') AS high,
                    COUNT(*) FILTER (WHERE rs.severity = 'MEDIUM') AS medium,
                    COUNT(*) FILTER (WHERE rs.severity = 'LOW') AS low,
                    AVG(rs.score) AS avg_score
                FROM nhi_identities n
                JOIN LATERAL (
                    SELECT score, severity
                    FROM risk_scores
                    WHERE nhi_id = n.id
                    ORDER BY computed_at DESC LIMIT 1
                ) rs ON true
            """)
        )
        scored_row = rows.mappings().first()

        # Count unscored NHIs (no risk_score row at all)
        unscored_row = await session.execute(
            text("""
                SELECT COUNT(*) AS unscored
                FROM nhi_identities n
                WHERE NOT EXISTS (
                    SELECT 1 FROM risk_scores WHERE nhi_id = n.id
                )
            """)
        )
        unscored = unscored_row.scalar_one()

        # Total NHIs
        total_row = await session.execute(text("SELECT COUNT(*) FROM nhi_identities"))
        total = total_row.scalar_one()

    scored = scored_row or {}
    return RiskStatsResponse(
        total=total,
        critical=scored.get("critical") or 0,
        high=scored.get("high") or 0,
        medium=scored.get("medium") or 0,
        low=scored.get("low") or 0,
        unscored=unscored,
        avg_score=float(scored.get("avg_score") or 0.0),
    )


async def get_risk_history(
    tenant_id: uuid.UUID, nhi_id: uuid.UUID, limit: int = 30
) -> list[RiskHistoryEntry]:
    async with tenant_session(tenant_id) as session:
        # Verify NHI exists
        exists = await session.execute(
            text("SELECT id FROM nhi_identities WHERE id = :id"),
            {"id": str(nhi_id)},
        )
        if not exists.first():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Identity not found")

        rows = await session.execute(
            text("""
                SELECT id, score, severity, factors, computed_at
                FROM risk_scores
                WHERE nhi_id = :nhi_id
                ORDER BY computed_at DESC
                LIMIT :limit
            """),
            {"nhi_id": str(nhi_id), "limit": limit},
        )
        records = rows.mappings().all()

    result = []
    for r in records:
        factors_raw = r["factors"]
        if isinstance(factors_raw, str):
            factors_raw = json.loads(factors_raw)
        result.append(
            RiskHistoryEntry(
                id=r["id"],
                score=float(r["score"]),
                severity=r["severity"],
                factors=factors_raw or [],
                computed_at=r["computed_at"],
            )
        )
    return result


async def get_top_risky(tenant_id: uuid.UUID, limit: int = 20) -> list[TopRiskyIdentity]:
    async with tenant_session(tenant_id) as session:
        rows = await session.execute(
            text("""
                SELECT
                    n.id,
                    n.name,
                    n.provider,
                    n.type,
                    rs.score,
                    rs.severity,
                    rs.factors
                FROM nhi_identities n
                JOIN LATERAL (
                    SELECT score, severity, factors
                    FROM risk_scores
                    WHERE nhi_id = n.id
                    ORDER BY computed_at DESC LIMIT 1
                ) rs ON true
                ORDER BY rs.score DESC
                LIMIT :limit
            """),
            {"limit": limit},
        )
        records = rows.mappings().all()

    result = []
    for r in records:
        factors_raw = r["factors"]
        if isinstance(factors_raw, str):
            factors_raw = json.loads(factors_raw)

        top_factor = None
        top_remediation = None
        if factors_raw:
            # Find factor with highest contribution
            best = max(factors_raw, key=lambda f: f.get("contribution", 0))
            top_factor = best.get("name")
            top_remediation = best.get("remediation")

        result.append(
            TopRiskyIdentity(
                id=r["id"],
                name=r["name"],
                provider=r["provider"],
                type=r["type"],
                score=float(r["score"]),
                severity=r["severity"],
                top_factor=top_factor,
                top_remediation=top_remediation,
            )
        )
    return result


async def recompute_all(tenant_id: uuid.UUID) -> int:
    from risk_engine.scorer import compute_risk_score
    from nhi_schema.models import NHIIdentity, NHIType, Provider, Classification, NHIStatus

    async with tenant_session(tenant_id) as session:
        rows = await session.execute(
            text("SELECT * FROM nhi_identities")
        )
        records = rows.mappings().all()

        count = 0
        for r in records:
            raw_meta = r.get("raw_metadata") or {}
            if isinstance(raw_meta, str):
                raw_meta = json.loads(raw_meta)

            # Build NHIIdentity from DB row
            try:
                identity = NHIIdentity(
                    id=r["id"],
                    tenant_id=tenant_id,
                    external_id=r["external_id"],
                    name=r["name"],
                    type=r["type"],
                    provider=r["provider"],
                    classification=r.get("classification") or "UNKNOWN",
                    owner_email=r.get("owner_email"),
                    created_at=r.get("created_at"),
                    last_used_at=r.get("last_used_at"),
                    last_rotated_at=r.get("last_rotated_at"),
                    status=r.get("status") or "ACTIVE",
                    raw_metadata=raw_meta,
                )
            except Exception:
                continue

            # Extract context from raw_metadata
            privilege_level = raw_meta.get("privilege_level", "standard")
            service_count = int(raw_meta.get("service_count", 1))
            granted_count = int(raw_meta.get("granted_count", 0))
            used_count = int(raw_meta.get("used_count", 0))
            account_scope = raw_meta.get("account_scope", "single")

            risk = compute_risk_score(
                identity,
                granted_count=granted_count,
                used_count=used_count,
                reachable_services=service_count,
                privilege_level=privilege_level,
                account_scope=account_scope,
            )

            score_id = uuid.uuid4()
            now = datetime.now(timezone.utc)

            await session.execute(
                text("""
                    INSERT INTO risk_scores (id, nhi_id, score, severity, factors, computed_at)
                    VALUES (:id, :nhi_id, :score, :severity, :factors, :computed_at)
                """),
                {
                    "id": str(score_id),
                    "nhi_id": str(r["id"]),
                    "score": risk.score,
                    "severity": risk.severity,
                    "factors": json.dumps([f.model_dump() for f in risk.factors]),
                    "computed_at": now,
                },
            )
            count += 1

    return count
