"""
Policy enforcer worker: long-polls SQS for scan.completed events and evaluates
all active policy rules against newly scanned NHIs. Inserts violations and fires
notifications for any new findings.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime, timezone

import boto3
import yaml

log = logging.getLogger(__name__)


def _simple_policy_check(nhi_row: dict, policy_yaml: str) -> bool:
    """
    Evaluate a YAML policy definition against an NHI row dict.
    Returns True if the NHI is in violation of the policy.
    No network dependency — purely deterministic Python.
    """
    try:
        policy = yaml.safe_load(policy_yaml)
    except yaml.YAMLError:
        return False

    applies_to = policy.get("applies_to", {})
    allowed_types = applies_to.get("types", [])
    allowed_providers = applies_to.get("providers", [])

    # Filter: if applies_to is specified, skip NHIs that don't match
    if allowed_types and nhi_row.get("type") not in allowed_types:
        return False
    if allowed_providers and nhi_row.get("provider") not in allowed_providers:
        return False

    conditions = policy.get("condition", {})

    # days_since_last_use condition
    if "days_since_last_use" in conditions:
        last_used = nhi_row.get("last_used_at")
        if last_used is None:
            days_since = 999999
        else:
            if hasattr(last_used, "tzinfo") and last_used.tzinfo is None:
                last_used = last_used.replace(tzinfo=timezone.utc)
            days_since = (datetime.now(timezone.utc) - last_used).days

        op_val = conditions["days_since_last_use"]
        for op, val in op_val.items():
            if op == "gte" and not (days_since >= val):
                return False
            elif op == "lte" and not (days_since <= val):
                return False
            elif op == "gt" and not (days_since > val):
                return False
            elif op == "lt" and not (days_since < val):
                return False

    # days_since_rotation condition
    if "days_since_rotation" in conditions:
        last_rotated = nhi_row.get("last_rotated_at")
        if last_rotated is None:
            days_since = 999999
        else:
            if hasattr(last_rotated, "tzinfo") and last_rotated.tzinfo is None:
                last_rotated = last_rotated.replace(tzinfo=timezone.utc)
            days_since = (datetime.now(timezone.utc) - last_rotated).days

        op_val = conditions["days_since_rotation"]
        for op, val in op_val.items():
            if op == "gte" and not (days_since >= val):
                return False
            elif op == "lte" and not (days_since <= val):
                return False
            elif op == "gt" and not (days_since > val):
                return False
            elif op == "lt" and not (days_since < val):
                return False

    return True


async def _enforce_policies(tenant_id_str: str) -> None:
    """Load NHIs and policies, evaluate, write violations, fire notifications."""
    from sqlalchemy import text
    from api.core.database import tenant_session
    from api.domains.integrations.service import send_notification

    tenant_id = uuid.UUID(tenant_id_str)

    async with tenant_session(tenant_id) as session:
        # Load all active NHIs
        nhi_rows_result = await session.execute(
            text("SELECT * FROM nhi_identities WHERE status NOT IN ('REVOKED')")
        )
        nhi_rows = nhi_rows_result.mappings().all()

        # Load all enabled policy rules
        policy_rows_result = await session.execute(
            text("SELECT * FROM policy_rules WHERE enabled = TRUE")
        )
        policy_rows = policy_rows_result.mappings().all()

        new_violations: list[dict] = []

        for nhi in nhi_rows:
            for policy in policy_rows:
                is_violation = _simple_policy_check(dict(nhi), policy["yaml_definition"])
                if not is_violation:
                    continue

                # Check if identical unresolved violation already exists
                existing = await session.execute(
                    text("""
                        SELECT id FROM policy_violations
                        WHERE nhi_id = :nhi_id AND policy_id = :policy_id AND resolved_at IS NULL
                    """),
                    {"nhi_id": str(nhi["id"]), "policy_id": str(policy["id"])},
                )
                if existing.first():
                    continue  # Already recorded

                violation_id = uuid.uuid4()
                now = datetime.now(timezone.utc)

                await session.execute(
                    text("""
                        INSERT INTO policy_violations
                            (id, nhi_id, policy_id, detected_at, metadata)
                        VALUES
                            (:id, :nhi_id, :policy_id, :detected_at, :metadata)
                    """),
                    {
                        "id": str(violation_id),
                        "nhi_id": str(nhi["id"]),
                        "policy_id": str(policy["id"]),
                        "detected_at": now,
                        "metadata": json.dumps({
                            "nhi_name": nhi.get("name"),
                            "policy_name": policy.get("name"),
                        }),
                    },
                )

                new_violations.append({
                    "nhi_id": str(nhi["id"]),
                    "nhi_name": nhi.get("name", ""),
                    "policy_id": str(policy["id"]),
                    "policy_name": policy.get("name", ""),
                    "enforcement_mode": policy.get("enforcement_mode", "MONITOR"),
                })

                # AUTO_REMEDIATE: publish rotation event
                if policy.get("enforcement_mode") == "AUTO_REMEDIATE":
                    from api.core.events import publish_rotation_requested
                    nhi_uuid = uuid.UUID(str(nhi["id"]))
                    await publish_rotation_requested(tenant_id, nhi_uuid, "policy_enforcer")
                    log.info(
                        "AUTO_REMEDIATE: queued rotation for NHI %s due to policy %s",
                        nhi["id"],
                        policy["id"],
                    )

    # Fire notifications for new violations (outside session)
    for v in new_violations:
        try:
            await send_notification(
                tenant_id=tenant_id,
                event_type="POLICY_VIOLATION",
                title=f"Policy violation: {v['policy_name']}",
                severity="HIGH",
                resource_type="NHIIdentity",
                resource_id=v["nhi_id"],
                description=f"NHI '{v['nhi_name']}' violates policy '{v['policy_name']}'.",
            )
        except Exception as exc:
            log.warning("Failed to send notification for violation: %s", exc)

    log.info(
        "Policy enforcement complete for tenant %s: %d new violations",
        tenant_id_str,
        len(new_violations),
    )


async def poll_scan_queue() -> None:
    sqs = boto3.client("sqs", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    queue_url = os.environ["SQS_SCAN_QUEUE_URL"]

    log.info("Policy enforcer polling queue: %s", queue_url)

    while True:
        try:
            resp = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=20,  # long-poll
            )
            messages = resp.get("Messages", [])

            for msg in messages:
                try:
                    envelope = json.loads(msg["Body"])
                    event_type = envelope.get("event_type", "")

                    # Only process scan.completed events
                    if event_type != "scan.completed":
                        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                        continue

                    tenant_id = envelope["tenant_id"]
                    await _enforce_policies(tenant_id)
                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                    log.info("Policy enforcement complete for tenant %s", tenant_id)

                except Exception as exc:
                    log.error("Failed to process scan message: %s", exc)

        except Exception as exc:
            log.error("Queue poll error: %s", exc)
            await asyncio.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(poll_scan_queue())
