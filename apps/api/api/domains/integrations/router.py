from __future__ import annotations

import uuid

from fastapi import APIRouter, Query, status

from api.core.auth import Auth

from .schemas import AlertResponse, WebhookCreate, WebhookResponse
from .service import (
    acknowledge_alert,
    create_webhook,
    delete_webhook,
    list_alerts,
    list_webhooks,
    test_webhook,
)

router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("/webhooks", response_model=list[WebhookResponse])
async def get_webhooks(auth: Auth = None):
    return await list_webhooks(auth.tenant_id)


@router.post("/webhooks", response_model=WebhookResponse, status_code=status.HTTP_201_CREATED)
async def add_webhook(body: WebhookCreate, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN")
    return await create_webhook(auth.tenant_id, body)


@router.delete("/webhooks/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_webhook(webhook_id: uuid.UUID, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN")
    await delete_webhook(auth.tenant_id, webhook_id)


@router.post("/webhooks/{webhook_id}/test")
async def fire_test_webhook(webhook_id: uuid.UUID, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN")
    return await test_webhook(auth.tenant_id, webhook_id)


@router.get("/alerts", response_model=list[AlertResponse])
async def get_alerts(
    status: str | None = Query(default=None),
    auth: Auth = None,
):
    return await list_alerts(auth.tenant_id, status_filter=status)


@router.post("/alerts/{alert_id}/acknowledge", status_code=status.HTTP_200_OK)
async def ack_alert(alert_id: uuid.UUID, auth: Auth = None):
    auth.require_role("OWNER", "ADMIN", "ANALYST")
    await acknowledge_alert(auth.tenant_id, alert_id, auth.user_id)
    return {"message": "Alert acknowledged", "alert_id": str(alert_id)}
