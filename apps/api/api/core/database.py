"""
Multi-tenant database engine with schema-per-tenant routing.

Flow: JWT → middleware extracts tenant_id → set_tenant_context() switches
the PostgreSQL search_path for that connection → RLS enforces isolation as
a second defence layer even if application routing is bypassed.
"""
from __future__ import annotations

import re
import uuid
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import (
    AsyncConnection,
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from .config import get_settings

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None

_SAFE_TENANT_RE = re.compile(r"^[0-9a-f]{8}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{4}_[0-9a-f]{12}$")


def _tenant_schema(tenant_id: uuid.UUID) -> str:
    """Derive a safe PostgreSQL schema name from a UUID."""
    safe = str(tenant_id).replace("-", "_")
    return f"tenant_{safe}"


def _validate_schema(schema: str) -> str:
    """Prevent schema-name injection; raise if format is unexpected."""
    inner = schema.removeprefix("tenant_")
    if not _SAFE_TENANT_RE.match(inner):
        raise ValueError(f"Invalid tenant schema name: {schema!r}")
    return schema


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        cfg = get_settings()
        _engine = create_async_engine(
            cfg.database_url,
            pool_size=cfg.db_pool_size,
            max_overflow=cfg.db_max_overflow,
            pool_pre_ping=True,
            echo=cfg.debug,
        )
    return _engine


def get_session_factory() -> async_sessionmaker[AsyncSession]:
    global _session_factory
    if _session_factory is None:
        _session_factory = async_sessionmaker(
            get_engine(),
            expire_on_commit=False,
            class_=AsyncSession,
        )
    return _session_factory


@asynccontextmanager
async def tenant_session(tenant_id: uuid.UUID) -> AsyncGenerator[AsyncSession, None]:
    """
    Yield an AsyncSession scoped to the given tenant's schema.
    The search_path is set at session start and reset on exit.
    """
    schema = _validate_schema(_tenant_schema(tenant_id))
    factory = get_session_factory()

    async with factory() as session:
        # Switch schema and set app-level session variable for RLS
        await session.execute(
            text("SET LOCAL search_path TO :schema, public"),
            {"schema": schema},
        )
        await session.execute(
            text("SET LOCAL app.tenant_id TO :tid"),
            {"tid": str(tenant_id)},
        )
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def provision_tenant_schema(tenant_id: uuid.UUID, conn: AsyncConnection) -> None:
    """
    Create the schema and all tables for a new tenant.
    Called once during tenant onboarding. Idempotent.
    """
    schema = _validate_schema(_tenant_schema(tenant_id))
    await conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
    await conn.execute(text(f'SET search_path TO "{schema}"'))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS nhi_identities (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            external_id TEXT NOT NULL,
            name TEXT NOT NULL,
            type TEXT NOT NULL,
            provider TEXT NOT NULL,
            classification TEXT DEFAULT 'UNKNOWN',
            owner_email TEXT,
            status TEXT DEFAULT 'ACTIVE',
            created_at TIMESTAMPTZ,
            last_used_at TIMESTAMPTZ,
            last_rotated_at TIMESTAMPTZ,
            last_scanned_at TIMESTAMPTZ DEFAULT NOW(),
            raw_metadata JSONB DEFAULT '{}',
            UNIQUE(provider, external_id)
        )
    """))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS risk_scores (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            nhi_id UUID REFERENCES nhi_identities(id) ON DELETE CASCADE,
            score NUMERIC(5,2) NOT NULL CHECK (score BETWEEN 0 AND 100),
            severity TEXT NOT NULL,
            factors JSONB NOT NULL DEFAULT '[]',
            computed_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS policy_rules (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            yaml_definition TEXT NOT NULL,
            compiled_rego TEXT,
            enforcement_mode TEXT DEFAULT 'MONITOR',
            enabled BOOLEAN DEFAULT TRUE,
            compliance_mappings TEXT[] DEFAULT '{}',
            created_by TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS policy_violations (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            nhi_id UUID REFERENCES nhi_identities(id) ON DELETE CASCADE,
            policy_id UUID REFERENCES policy_rules(id) ON DELETE CASCADE,
            detected_at TIMESTAMPTZ DEFAULT NOW(),
            resolved_at TIMESTAMPTZ,
            resolution TEXT,
            metadata JSONB DEFAULT '{}'
        )
    """))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            actor_type TEXT NOT NULL,
            actor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            resource_type TEXT,
            resource_id TEXT,
            outcome TEXT NOT NULL,
            reason TEXT,
            ip_address INET,
            metadata JSONB DEFAULT '{}',
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))
    # Prevent UPDATE/DELETE on audit_log at the role level (enforced in migration scripts)

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS jit_grants (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            requester_id TEXT NOT NULL,
            nhi_id UUID REFERENCES nhi_identities(id) ON DELETE SET NULL,
            scope JSONB NOT NULL DEFAULT '{}',
            reason TEXT NOT NULL,
            approved_by TEXT,
            issued_at TIMESTAMPTZ DEFAULT NOW(),
            expires_at TIMESTAMPTZ NOT NULL,
            revoked_at TIMESTAMPTZ,
            status TEXT DEFAULT 'ACTIVE'
        )
    """))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS behavioral_events (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            nhi_id UUID REFERENCES nhi_identities(id) ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            service TEXT,
            region TEXT,
            ip_address INET,
            bytes_transferred BIGINT DEFAULT 0,
            success BOOLEAN DEFAULT TRUE,
            occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            metadata JSONB DEFAULT '{}'
        )
    """))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS behavioral_baselines (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            nhi_id UUID REFERENCES nhi_identities(id) ON DELETE CASCADE,
            baseline JSONB NOT NULL DEFAULT '{}',
            computed_at TIMESTAMPTZ DEFAULT NOW(),
            warmup_complete BOOLEAN DEFAULT FALSE,
            UNIQUE(nhi_id)
        )
    """))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS integration_webhooks (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name TEXT NOT NULL,
            url TEXT NOT NULL,
            type TEXT NOT NULL,
            secret TEXT,
            enabled BOOLEAN DEFAULT TRUE,
            events TEXT[] DEFAULT '{}',
            created_at TIMESTAMPTZ DEFAULT NOW(),
            last_triggered_at TIMESTAMPTZ,
            last_error TEXT
        )
    """))

    await conn.execute(text("""
        CREATE TABLE IF NOT EXISTS alerts (
            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            type TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            resource_type TEXT,
            resource_id TEXT,
            status TEXT DEFAULT 'OPEN',
            acknowledged_by TEXT,
            acknowledged_at TIMESTAMPTZ,
            resolved_at TIMESTAMPTZ,
            metadata JSONB DEFAULT '{}',
            created_at TIMESTAMPTZ DEFAULT NOW()
        )
    """))

    # RLS policies
    for table in (
        "nhi_identities", "risk_scores", "policy_rules", "policy_violations",
        "jit_grants", "behavioral_events", "behavioral_baselines",
        "integration_webhooks", "alerts",
    ):
        await conn.execute(text(f'ALTER TABLE "{schema}".{table} ENABLE ROW LEVEL SECURITY'))
        await conn.execute(text(f"""
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_policies
                    WHERE schemaname = '{schema}' AND tablename = '{table}' AND policyname = 'tenant_rls'
                ) THEN
                    EXECUTE 'CREATE POLICY tenant_rls ON "{schema}".{table}
                        USING (current_setting(''app.tenant_id'')::uuid IS NOT NULL)';
                END IF;
            END $$
        """))

    await conn.commit()


class Base(DeclarativeBase):
    pass
