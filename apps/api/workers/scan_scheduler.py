"""
Scan scheduler worker: consumes scan.requested events from SQS and
instructs the appropriate sensor(s) to run a scan cycle.
Runs as a separate process alongside the FastAPI app.
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
    sensor_base = os.environ.get("SENSOR_CALLBACK_URL", "")

    import httpx

    log.info("Scan scheduler polling queue: %s", queue_url)

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
                    tenant_id = envelope["tenant_id"]
                    providers = envelope["payload"].get("providers", [])

                    if sensor_base:
                        async with httpx.AsyncClient() as client:
                            await client.post(
                                f"{sensor_base}/scan",
                                json={"tenant_id": tenant_id, "providers": providers},
                                timeout=10.0,
                            )

                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                    log.info("Dispatched scan for tenant %s providers %s", tenant_id, providers)
                except Exception as exc:
                    log.error("Failed to process scan message: %s", exc)

        except Exception as exc:
            log.error("Queue poll error: %s", exc)
            await asyncio.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(poll_scan_queue())
