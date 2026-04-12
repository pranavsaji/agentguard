"""
Policy engine: persists YAML policy definitions and evaluates them via OPA.
The YAML DSL is compiled to Rego by the rego_compiler module before storage.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import httpx
import yaml
from fastapi import HTTPException, status
from sqlalchemy import text

from api.core.config import get_settings
from api.core.database import tenant_session

from .schemas import PolicyCreate, PolicyResponse, PolicyUpdate, ViolationResponse


# ---------------------------------------------------------------------------
# DSL → Rego compilation (minimal v1: translates simple condition blocks)
# ---------------------------------------------------------------------------

def _compile_yaml_to_rego(name: str, yaml_def: str) -> str:
    """
    Compile AgentGuard policy YAML into an OPA Rego module.
    Supports condition keys: days_since_last_use, days_since_rotation, type, provider.
    """
    try:
        policy = yaml.safe_load(yaml_def)
    except yaml.YAMLError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"Invalid YAML: {exc}")

    conditions = policy.get("condition", {})
    applies_to = policy.get("applies_to", {})
    types = applies_to.get("types", [])
    providers = applies_to.get("providers", [])

    rego_conditions: list[str] = []

    if types:
        types_str = ", ".join(f'"{t}"' for t in types)
        rego_conditions.append(f"input.type in {{{types_str}}}")
    if providers:
        providers_str = ", ".join(f'"{p}"' for p in providers)
        rego_conditions.append(f"input.provider in {{{providers_str}}}")
    if "days_since_last_use" in conditions:
        op_val = conditions["days_since_last_use"]
        op, val = list(op_val.items())[0]
        op_map = {"gte": ">=", "lte": "<=", "gt": ">", "lt": "<"}
        rego_conditions.append(f"input.days_since_last_use {op_map[op]} {val}")
    if "days_since_rotation" in conditions:
        op_val = conditions["days_since_rotation"]
        op, val = list(op_val.items())[0]
        op_map = {"gte": ">=", "lte": "<=", "gt": ">", "lt": "<"}
        rego_conditions.append(f"input.days_since_rotation {op_map[op]} {val}")

    conditions_rego = "\n    ".join(rego_conditions) or "true"
    safe_name = name.replace("-", "_").replace(" ", "_").lower()

    return f"""package agentguard.policies.{safe_name}

default violation = false

violation {{
    {conditions_rego}
}}
"""


async def _opa_check(rego: str, input_data: dict, enforcement_mode: str = "MONITOR") -> bool:
    """
    Evaluate a Rego policy against input via OPA REST API.
    Fail-closed for ENFORCE/AUTO_REMEDIATE (security posture: deny on uncertainty).
    Fail-open for MONITOR/ALERT (observability only; blocking would be disruptive).
    """
    cfg = get_settings()
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.post(
                f"{cfg.opa_url}/v1/data",
                json={"rego_modules": {"policy": rego}, "input": input_data},
            )
            resp.raise_for_status()
            result = resp.json()
            return result.get("result", {}).get("violation", False)
    except Exception:
        # CISO principle: enforcement modes must be deterministic.
        # If OPA is unreachable, blocking modes deny the operation; observability modes skip.
        if enforcement_mode in ("ENFORCE", "AUTO_REMEDIATE"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Policy engine unavailable — request blocked in ENFORCE mode.",
            )
        return False


async def create_policy(tenant_id: uuid.UUID, data: PolicyCreate, actor_id: str) -> PolicyResponse:
    compiled_rego = _compile_yaml_to_rego(data.name, data.yaml_definition)
    policy_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    async with tenant_session(tenant_id) as session:
        await session.execute(
            text("""
                INSERT INTO policy_rules
                    (id, name, description, yaml_definition, compiled_rego,
                     enforcement_mode, enabled, compliance_mappings, created_by, created_at)
                VALUES
                    (:id, :name, :description, :yaml_definition, :compiled_rego,
                     :enforcement_mode, true, :compliance_mappings, :created_by, :created_at)
            """),
            {
                "id": str(policy_id),
                "name": data.name,
                "description": data.description,
                "yaml_definition": data.yaml_definition,
                "compiled_rego": compiled_rego,
                "enforcement_mode": data.enforcement_mode,
                "compliance_mappings": data.compliance_mappings,
                "created_by": actor_id,
                "created_at": now,
            },
        )

    return PolicyResponse(
        id=policy_id,
        name=data.name,
        description=data.description,
        yaml_definition=data.yaml_definition,
        enforcement_mode=data.enforcement_mode,
        enabled=True,
        compliance_mappings=data.compliance_mappings,
        created_by=actor_id,
        created_at=now,
    )


async def list_policies(tenant_id: uuid.UUID) -> list[PolicyResponse]:
    async with tenant_session(tenant_id) as session:
        rows = await session.execute(
            text("SELECT * FROM policy_rules ORDER BY created_at DESC")
        )
        return [PolicyResponse(**dict(r)) for r in rows.mappings()]


async def update_policy(tenant_id: uuid.UUID, policy_id: uuid.UUID, data: PolicyUpdate) -> PolicyResponse:
    updates = {k: v for k, v in data.model_dump().items() if v is not None}

    if "yaml_definition" in updates:
        # Recompile Rego when YAML changes
        updates["compiled_rego"] = _compile_yaml_to_rego(policy_id.hex, updates["yaml_definition"])

    updates["updated_at"] = datetime.now(timezone.utc)
    set_clause = ", ".join(f"{k} = :{k}" for k in updates)

    async with tenant_session(tenant_id) as session:
        result = await session.execute(
            text(f"UPDATE policy_rules SET {set_clause} WHERE id = :id RETURNING *"),
            {**updates, "id": str(policy_id)},
        )
        row = result.mappings().first()
        if not row:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Policy not found")
        return PolicyResponse(**dict(row))


async def list_violations(tenant_id: uuid.UUID, policy_id: uuid.UUID | None = None) -> list[ViolationResponse]:
    where = "1=1"
    params: dict = {}
    if policy_id:
        where = "pv.policy_id = :policy_id"
        params["policy_id"] = str(policy_id)

    async with tenant_session(tenant_id) as session:
        rows = await session.execute(
            text(f"""
                SELECT pv.*, pr.name AS policy_name
                FROM policy_violations pv
                JOIN policy_rules pr ON pr.id = pv.policy_id
                WHERE {where}
                ORDER BY pv.detected_at DESC
                LIMIT 500
            """),
            params,
        )
        return [ViolationResponse(**dict(r)) for r in rows.mappings()]
