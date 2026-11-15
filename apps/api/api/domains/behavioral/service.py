from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import text

from api.core.database import tenant_session

from .schemas import (
    AnomalyFlag,
    BaselineStatus,
    BehavioralEventCreate,
    BehavioralEventResponse,
)


async def ingest_events(
    tenant_id: uuid.UUID, events: list[BehavioralEventCreate]
) -> int:
    now = datetime.now(timezone.utc)
    async with tenant_session(tenant_id) as session:
        count = 0
        for event in events:
            event_id = uuid.uuid4()
            occurred_at = event.occurred_at or now
            await session.execute(
                text("""
                    INSERT INTO behavioral_events
                        (id, nhi_id, event_type, service, region, ip_address,
                         bytes_transferred, success, occurred_at, metadata)
                    VALUES
                        (:id, :nhi_id, :event_type, :service, :region, :ip_address,
                         :bytes_transferred, :success, :occurred_at, :metadata)
                """),
                {
                    "id": str(event_id),
                    "nhi_id": str(event.nhi_id),
                    "event_type": event.event_type,
                    "service": event.service,
                    "region": event.region,
                    "ip_address": event.ip_address,
                    "bytes_transferred": event.bytes_transferred,
                    "success": event.success,
                    "occurred_at": occurred_at,
                    "metadata": json.dumps(event.metadata),
                },
            )
            count += 1
    return count


async def get_timeline(
    tenant_id: uuid.UUID, nhi_id: uuid.UUID, hours: int = 24
) -> list[BehavioralEventResponse]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    async with tenant_session(tenant_id) as session:
        rows = await session.execute(
            text("""
                SELECT id, nhi_id, event_type, service, region, success, occurred_at
                FROM behavioral_events
                WHERE nhi_id = :nhi_id AND occurred_at >= :cutoff
                ORDER BY occurred_at DESC
                LIMIT 200
            """),
            {"nhi_id": str(nhi_id), "cutoff": cutoff},
        )
        records = rows.mappings().all()

    return [
        BehavioralEventResponse(
            id=r["id"],
            nhi_id=r["nhi_id"],
            event_type=r["event_type"],
            service=r.get("service"),
            region=r.get("region"),
            success=r["success"],
            occurred_at=r["occurred_at"],
        )
        for r in records
    ]


async def get_anomalies(tenant_id: uuid.UUID) -> list[AnomalyFlag]:
    now = datetime.now(timezone.utc)
    cutoff_24h = now - timedelta(hours=24)

    async with tenant_session(tenant_id) as session:
        # Check if any baselines exist
        baseline_count_row = await session.execute(
            text("SELECT COUNT(*) FROM behavioral_baselines WHERE warmup_complete = TRUE")
        )
        if baseline_count_row.scalar_one() == 0:
            return []

        # Load all baselines with warmup_complete
        baselines = await session.execute(
            text("""
                SELECT bb.nhi_id, bb.baseline_data, n.name AS nhi_name
                FROM behavioral_baselines bb
                JOIN nhi_identities n ON n.id = bb.nhi_id
                WHERE bb.warmup_complete = TRUE
            """)
        )
        baseline_records = baselines.mappings().all()

        flags: list[AnomalyFlag] = []

        for b in baseline_records:
            nhi_id = b["nhi_id"]
            nhi_name = b["nhi_name"]
            baseline_data = b["baseline_data"]
            if isinstance(baseline_data, str):
                baseline_data = json.loads(baseline_data)

            # Load last-24h metrics for this NHI
            metrics_row = await session.execute(
                text("""
                    SELECT
                        COUNT(*) AS event_count,
                        COUNT(*) FILTER (WHERE event_type = 'AUTH_FAILURE') AS auth_failures,
                        COUNT(*) FILTER (WHERE event_type IN ('AUTH_SUCCESS','AUTH_FAILURE')) AS auth_total,
                        array_agg(DISTINCT service) FILTER (WHERE service IS NOT NULL) AS services_used
                    FROM behavioral_events
                    WHERE nhi_id = :nhi_id AND occurred_at >= :cutoff
                """),
                {"nhi_id": str(nhi_id), "cutoff": cutoff_24h},
            )
            m = metrics_row.mappings().first()

            signals: list[str] = []
            event_count = m["event_count"] or 0
            auth_failures = m["auth_failures"] or 0
            auth_total = m["auth_total"] or 0
            services_used = m["services_used"] or []

            # Rule 1: auth_failure_rate > 0.3
            if auth_total > 0:
                failure_rate = auth_failures / auth_total
                if failure_rate > 0.3:
                    signals.append(
                        f"High auth failure rate: {failure_rate:.0%} ({auth_failures}/{auth_total} auth events failed)"
                    )

            # Rule 2: event_count > 3x baseline avg
            baseline_avg = float(baseline_data.get("avg_events_per_day", 0))
            if baseline_avg > 0 and event_count > 3 * baseline_avg:
                signals.append(
                    f"Event volume spike: {event_count} events in 24h vs baseline avg {baseline_avg:.1f}/day"
                )

            # Rule 3: new services not in baseline
            typical_services = set(baseline_data.get("typical_services", []))
            new_services = [s for s in services_used if s not in typical_services]
            if new_services:
                signals.append(
                    f"Access to new services not in baseline: {', '.join(new_services)}"
                )

            if signals:
                # Simple anomaly score: 1/3 weight per signal type triggered
                anomaly_score = min(1.0, len(signals) / 3.0)
                flags.append(
                    AnomalyFlag(
                        nhi_id=nhi_id,
                        nhi_name=nhi_name,
                        anomaly_score=round(anomaly_score, 3),
                        signals=signals,
                    )
                )

    return flags


async def compute_baseline(tenant_id: uuid.UUID, nhi_id: uuid.UUID) -> BaselineStatus:
    now = datetime.now(timezone.utc)
    cutoff_14d = now - timedelta(days=14)

    async with tenant_session(tenant_id) as session:
        # Count events in last 14 days
        count_row = await session.execute(
            text("""
                SELECT
                    COUNT(*) AS event_count_14d,
                    MIN(occurred_at) AS oldest_event,
                    AVG(daily_count) AS avg_events_per_day
                FROM (
                    SELECT DATE(occurred_at) AS day, COUNT(*) AS daily_count
                    FROM behavioral_events
                    WHERE nhi_id = :nhi_id AND occurred_at >= :cutoff
                    GROUP BY DATE(occurred_at)
                ) daily
            """),
            {"nhi_id": str(nhi_id), "cutoff": cutoff_14d},
        )
        stats = count_row.mappings().first()

        event_count_14d = stats["event_count_14d"] or 0

        # Services used in last 14 days
        services_row = await session.execute(
            text("""
                SELECT array_agg(DISTINCT service) FILTER (WHERE service IS NOT NULL) AS typical_services
                FROM behavioral_events
                WHERE nhi_id = :nhi_id AND occurred_at >= :cutoff
            """),
            {"nhi_id": str(nhi_id), "cutoff": cutoff_14d},
        )
        services_data = services_row.mappings().first()
        typical_services = services_data["typical_services"] or []

        # Auth failure rate in last 14 days
        auth_row = await session.execute(
            text("""
                SELECT
                    COUNT(*) FILTER (WHERE event_type = 'AUTH_FAILURE') AS failures,
                    COUNT(*) FILTER (WHERE event_type IN ('AUTH_SUCCESS', 'AUTH_FAILURE')) AS total_auth
                FROM behavioral_events
                WHERE nhi_id = :nhi_id AND occurred_at >= :cutoff
            """),
            {"nhi_id": str(nhi_id), "cutoff": cutoff_14d},
        )
        auth_data = auth_row.mappings().first()
        failures = auth_data["failures"] or 0
        total_auth = auth_data["total_auth"] or 0
        avg_auth_failure_rate = (failures / total_auth) if total_auth > 0 else 0.0

        # Check if we have > 14 days of data
        oldest_row = await session.execute(
            text("SELECT MIN(occurred_at) AS oldest FROM behavioral_events WHERE nhi_id = :nhi_id"),
            {"nhi_id": str(nhi_id)},
        )
        oldest_data = oldest_row.mappings().first()
        oldest_event = oldest_data["oldest"] if oldest_data else None

        warmup_complete = False
        if oldest_event is not None:
            # Make oldest_event timezone-aware if needed
            if oldest_event.tzinfo is None:
                oldest_event = oldest_event.replace(tzinfo=timezone.utc)
            warmup_complete = (now - oldest_event).days > 14

        baseline_data = {
            "avg_events_per_day": float(stats["avg_events_per_day"] or 0),
            "typical_services": list(typical_services),
            "avg_auth_failure_rate": avg_auth_failure_rate,
        }

        # UPSERT into behavioral_baselines
        await session.execute(
            text("""
                INSERT INTO behavioral_baselines (nhi_id, warmup_complete, baseline_data, computed_at)
                VALUES (:nhi_id, :warmup_complete, :baseline_data, :computed_at)
                ON CONFLICT (nhi_id) DO UPDATE SET
                    warmup_complete = EXCLUDED.warmup_complete,
                    baseline_data = EXCLUDED.baseline_data,
                    computed_at = EXCLUDED.computed_at
            """),
            {
                "nhi_id": str(nhi_id),
                "warmup_complete": warmup_complete,
                "baseline_data": json.dumps(baseline_data),
                "computed_at": now,
            },
        )

    return BaselineStatus(
        nhi_id=nhi_id,
        warmup_complete=warmup_complete,
        computed_at=now,
        event_count_14d=event_count_14d,
    )
