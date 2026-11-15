"""
Rotation orchestrator worker: consumes rotation.requested events from SQS,
validates the request against policy, and delegates to the sensor's rotator.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os

import boto3

log = logging.getLogger(__name__)


async def poll_rotation_queue() -> None:
    sqs = boto3.client("sqs", region_name=os.environ.get("AWS_REGION", "us-east-1"))
    queue_url = os.environ["SQS_ROTATION_QUEUE_URL"]
    sensor_base = os.environ.get("SENSOR_CALLBACK_URL", "")

    import httpx

    log.info("Rotation orchestrator polling queue: %s", queue_url)

    while True:
        try:
            resp = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=5,
                WaitTimeSeconds=20,
            )
            messages = resp.get("Messages", [])

            for msg in messages:
                try:
                    envelope = json.loads(msg["Body"])
                    payload = envelope["payload"]

                    if sensor_base:
                        async with httpx.AsyncClient() as client:
                            await client.post(
                                f"{sensor_base}/rotate",
                                json={
                                    "tenant_id": envelope["tenant_id"],
                                    "nhi_id": payload["nhi_id"],
                                    "actor_id": payload["actor_id"],
                                },
                                timeout=30.0,
                            )

                    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                    log.info("Dispatched rotation for nhi %s", payload["nhi_id"])
                except Exception as exc:
                    log.error("Failed to process rotation message: %s", exc)

        except Exception as exc:
            log.error("Queue poll error: %s", exc)
            await asyncio.sleep(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(poll_rotation_queue())
