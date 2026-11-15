from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import HTTPException, status
from sqlalchemy import text

from api.core.database import tenant_session

from .schemas import AlertResponse, WebhookCreate, WebhookResponse

log = logging.getLogger(__name__)


def _build_payload(webhook_type: str, title: str, severity: str, description: str | None) -> dict:
    if webhook_type == "SLACK":
        return {
            "text": f"*[AgentGuard] {severity}: {title}*\n{description or ''}",
        }
    elif webhook_type == "PAGERDUTY":
        return {
            "payload": {
                "summary": title,
                "severity": severity.lower(),
                "source": "agentguard",
                "custom_details": {"description": description or ""},
            },
            "event_action": "trigger",
        }
    else:
        return {
            "event": title,
            "severity": severity,
            "source": "agentguard",
            "message": description or "",
        }


def _row_to_webhook(r: dict) -> WebhookResponse:
    events_raw = r["events"]
    if isinstance(events_raw, str):
        events_raw = json.loads(events_raw)
    return WebhookResponse(
        id=r["id"],
        name=r["name"],
        url=r["url"],
        type=r["type"],
        enabled=r["enabled"],
        events=events_raw or [],
        created_at=r["created_at"],
        last_triggered_at=r.get("last_triggered_at"),
        last_error=r.get("last_error"),
    )


async def create_webhook(tenant_id: uuid.UUID, data: WebhookCreate) -> WebhookResponse:
    webhook_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    async with tenant_session(tenant_id) as session:
        await session.execute(
            text("""
                INSERT INTO integration_webhooks
                    (id, name, url, type, secret, events, enabled, created_at)
                VALUES
                    (:id, :name, :url, :type, :secret, :events, TRUE, :created_at)
            """),
            {
                "id": str(webhook_id),
                "name": data.name,
                "url": data.url,
                "type": data.type,
                "secret": data.secret,
                "events": json.dumps(data.events),
                "created_at": now,
            },
        )
        row = await session.execute(
            text("SELECT * FROM integration_webhooks WHERE id = :id"),
            {"id": str(webhook_id)},
        )
        record = row.mappings().first()

    return _row_to_webhook(dict(record))


async def list_webhooks(tenant_id: uuid.UUID) -> list[WebhookResponse]:
    async with tenant_session(tenant_id) as session:
        rows = await session.execute(
            text("SELECT * FROM integration_webhooks WHERE enabled = TRUE ORDER BY created_at DESC")
        )
        records = rows.mappings().all()

    return [_row_to_webhook(dict(r)) for r in records]


async def delete_webhook(tenant_id: uuid.UUID, webhook_id: uuid.UUID) -> None:
    async with tenant_session(tenant_id) as session:
        result = await session.execute(
            text("""
                UPDATE integration_webhooks
                SET enabled = FALSE
                WHERE id = :id AND enabled = TRUE
                RETURNING id
            """),
            {"id": str(webhook_id)},
        )
        if not result.first():
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")


async def test_webhook(tenant_id: uuid.UUID, webhook_id: uuid.UUID) -> dict:
    async with tenant_session(tenant_id) as session:
        row = await session.execute(
            text("SELECT * FROM integration_webhooks WHERE id = :id AND enabled = TRUE"),
            {"id": str(webhook_id)},
        )
        record = row.mappings().first()

    if not record:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Webhook not found")

    webhook_type = record["type"]
    url = record["url"]

    if webhook_type == "SLACK":
        payload = {"text": "AgentGuard test notification from tenant webhook"}
    elif webhook_type == "PAGERDUTY":
        routing_key = record.get("secret") or ""
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": "AgentGuard test notification",
                "severity": "info",
                "source": "agentguard",
            },
        }
    else:
        payload = {"event": "TEST", "source": "agentguard", "message": "Test notification"}

    success = False
    http_status_code = None
    error_msg = None

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
            http_status_code = resp.status_code
            resp.raise_for_status()
            success = True
    except httpx.HTTPStatusError as exc:
        http_status_code = exc.response.status_code
        error_msg = f"HTTP {http_status_code}: {exc.response.text[:200]}"
    except Exception as exc:
        error_msg = str(exc)[:500]

    now = datetime.now(timezone.utc)
    async with tenant_session(tenant_id) as session:
        if success:
            await session.execute(
                text("""
                    UPDATE integration_webhooks
                    SET last_triggered_at = :now, last_error = NULL
                    WHERE id = :id
                """),
                {"now": now, "id": str(webhook_id)},
            )
        else:
            await session.execute(
                text("""
                    UPDATE integration_webhooks
                    SET last_triggered_at = :now, last_error = :error
                    WHERE id = :id
                """),
                {"now": now, "error": error_msg, "id": str(webhook_id)},
            )

    return {"success": success, "status_code": http_status_code, "error": error_msg}


async def send_notification(
    tenant_id: uuid.UUID,
    event_type: str,
    title: str,
    severity: str,
    resource_type: str | None = None,
    resource_id: str | None = None,
    description: str | None = None,
) -> None:
    alert_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    async with tenant_session(tenant_id) as session:
        # INSERT into alerts
        await session.execute(
            text("""
                INSERT INTO alerts
                    (id, type, severity, title, description, resource_type, resource_id, status, created_at)
                VALUES
                    (:id, :type, :severity, :title, :description, :resource_type, :resource_id, 'OPEN', :created_at)
            """),
            {
                "id": str(alert_id),
                "type": event_type,
                "severity": severity,
                "title": title,
                "description": description,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "created_at": now,
            },
        )

        # Load matching webhooks
        rows = await session.execute(
            text("""
                SELECT * FROM integration_webhooks
                WHERE enabled = TRUE
                  AND (:event_type = ANY(events) OR events = '[]' OR events = '{}')
            """),
            {"event_type": event_type},
        )
        webhooks = rows.mappings().all()

    # Fire webhooks outside the session (async, non-blocking on failure)
    for wh in webhooks:
        wh_type = wh["type"]
        url = wh["url"]
        wh_id = wh["id"]

        if wh_type == "SLACK":
            payload = {"text": f"*[AgentGuard] {severity}: {title}*\n{description or ''}"}
        elif wh_type == "PAGERDUTY":
            routing_key = wh.get("secret") or ""
            payload = {
                "routing_key": routing_key,
                "event_action": "trigger",
                "payload": {
                    "summary": title,
                    "severity": severity.lower(),
                    "source": "agentguard",
                    "custom_details": {"description": description or ""},
                },
            }
        else:
            payload = {
                "event": event_type,
                "severity": severity,
                "source": "agentguard",
                "message": description or "",
                "title": title,
            }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
            fire_error = None
        except Exception as exc:
            fire_error = str(exc)[:500]
            log.warning("Webhook %s delivery failed: %s", wh_id, fire_error)

        # Update last_triggered_at and last_error
        try:
            async with tenant_session(tenant_id) as session:
                await session.execute(
                    text("""
                        UPDATE integration_webhooks
                        SET last_triggered_at = :now, last_error = :error
                        WHERE id = :id
                    """),
                    {"now": now, "error": fire_error, "id": str(wh_id)},
                )
        except Exception as exc:
            log.warning("Failed to update webhook delivery status for %s: %s", wh_id, exc)


async def list_alerts(
    tenant_id: uuid.UUID, status_filter: str | None = None
) -> list[AlertResponse]:
    where = "1=1"
    params: dict = {}
    if status_filter:
        where = "status = :status"
        params["status"] = status_filter

    async with tenant_session(tenant_id) as session:
        rows = await session.execute(
            text(f"""
                SELECT id, type, severity, title, description, resource_type, resource_id, status, created_at
                FROM alerts
                WHERE {where}
                ORDER BY created_at DESC
                LIMIT 100
            """),
            params,
        )
        records = rows.mappings().all()

    return [
        AlertResponse(
            id=r["id"],
            type=r["type"],
            severity=r["severity"],
            title=r["title"],
            description=r.get("description"),
            resource_type=r.get("resource_type"),
            resource_id=r.get("resource_id"),
            status=r["status"],
            created_at=r["created_at"],
        )
        for r in records
    ]


async def acknowledge_alert(
    tenant_id: uuid.UUID, alert_id: uuid.UUID, actor_id: str
) -> None:
    now = datetime.now(timezone.utc)
    async with tenant_session(tenant_id) as session:
        result = await session.execute(
            text("""
                UPDATE alerts
                SET status = 'ACKNOWLEDGED', acknowledged_by = :actor_id, acknowledged_at = :now
                WHERE id = :id AND status != 'ACKNOWLEDGED'
                RETURNING id
            """),
            {"id": str(alert_id), "actor_id": actor_id, "now": now},
        )
        if not result.first():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Alert not found or already acknowledged",
            )
