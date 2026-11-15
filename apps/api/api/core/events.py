"""
Event bus: publishes domain events to SQS for async processing by workers.
Uses a simple envelope schema so consumers can route by event_type without
deserializing the full payload.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from .config import get_settings

_sqs: Any = None


def _get_sqs():
    global _sqs
    if _sqs is None:
        cfg = get_settings()
        _sqs = boto3.client("sqs", region_name=cfg.aws_region)
    return _sqs


def _envelope(event_type: str, payload: dict, tenant_id: uuid.UUID) -> str:
    return json.dumps(
        {
            "event_id": str(uuid.uuid4()),
            "event_type": event_type,
            "tenant_id": str(tenant_id),
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "payload": payload,
        },
        default=str,
    )


async def publish_scan_requested(tenant_id: uuid.UUID, providers: list[str]) -> None:
    cfg = get_settings()
    if not cfg.sqs_scan_queue_url:
        return
    body = _envelope("scan.requested", {"providers": providers}, tenant_id)
    _get_sqs().send_message(QueueUrl=cfg.sqs_scan_queue_url, MessageBody=body)


async def publish_rotation_requested(
    tenant_id: uuid.UUID,
    nhi_id: uuid.UUID,
    actor_id: str,
) -> None:
    cfg = get_settings()
    if not cfg.sqs_rotation_queue_url:
        return
    body = _envelope(
        "rotation.requested",
        {"nhi_id": str(nhi_id), "actor_id": actor_id},
        tenant_id,
    )
    _get_sqs().send_message(QueueUrl=cfg.sqs_rotation_queue_url, MessageBody=body)


async def publish_anomaly_detected(
    tenant_id: uuid.UUID,
    nhi_id: uuid.UUID,
    anomaly_score: float,
    features: dict,
) -> None:
    cfg = get_settings()
    if not cfg.sqs_scan_queue_url:
        return
    body = _envelope(
        "anomaly.detected",
        {"nhi_id": str(nhi_id), "anomaly_score": anomaly_score, "features": features},
        tenant_id,
    )
    _get_sqs().send_message(QueueUrl=cfg.sqs_scan_queue_url, MessageBody=body)
