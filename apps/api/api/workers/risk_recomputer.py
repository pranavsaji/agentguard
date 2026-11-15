"""
Risk recomputer worker: long-polls SQS for scan.completed events and triggers
a full risk score recomputation for the affected tenant.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

import boto3

log = logging.getLogger(__name__)


async def poll_scan_queue() -> None:
    sqs = boto3.client("sqs", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    queue_url = os.environ["SQS_SCAN_QUEUE_URL"]

    log.info("Risk recomputer polling queue: %s", queue_url)

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

                    tenant_id_str = envelope["tenant_id"]

                    import uuid
                    from api.domains.risk.service import recompute_all

                    tenant_id = uuid.UUID(tenant_id_str)
                    count = await recompute_all(tenant_id)

                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                    log.info(
                        "Risk recomputation complete for tenant %s: %d NHIs scored",
                        tenant_id_str,
                        count,
                    )

                except Exception as exc:
                    log.error("Failed to process scan message: %s", exc)

        except Exception as exc:
            log.error("Queue poll error: %s", exc)
            await asyncio.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(poll_scan_queue())
