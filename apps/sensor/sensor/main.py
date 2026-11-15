"""
AgentGuard Sensor entrypoint.
Runs scheduled scans across all configured cloud providers and streams
results back to the control plane API over HTTPS.
"""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any

import httpx

from sensor.connectors.aws.iam_scanner import AWSIAMScanner
from sensor.connectors.azure.entra_scanner import AzureEntraScanner
from sensor.connectors.base import BaseConnector, ConnectorConfig
from sensor.connectors.gcp.iam_scanner import GCPIAMScanner
from sensor.connectors.github.secrets_scanner import GitHubScanner
from nhi_schema.models import Provider, ScanResult

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

CONTROL_PLANE_URL = os.environ["AGENTGUARD_CONTROL_PLANE_URL"]
SENSOR_TOKEN = os.environ["AGENTGUARD_SENSOR_TOKEN"]
TENANT_ID = uuid.UUID(os.environ["AGENTGUARD_TENANT_ID"])

PROVIDER_MAP: dict[str, type[BaseConnector]] = {
    Provider.AWS: AWSIAMScanner,
    Provider.AZURE: AzureEntraScanner,
    Provider.GCP: GCPIAMScanner,
    Provider.GITHUB: GitHubScanner,
}


def _build_connector(provider: str, tenant_id: uuid.UUID) -> BaseConnector | None:
    """Instantiate a connector from environment-provided credentials."""
    cls = PROVIDER_MAP.get(provider)
    if cls is None:
        return None

    credentials: dict[str, Any] = {}

    if provider == Provider.AWS:
        role_arn = os.environ.get("AWS_ROLE_ARN")
        if role_arn:
            import boto3
            sts = boto3.client("sts")
            assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName="agentguard-sensor")["Credentials"]
            credentials = {
                "aws_access_key_id": assumed["AccessKeyId"],
                "aws_secret_access_key": assumed["SecretAccessKey"],
                "aws_session_token": assumed["SessionToken"],
                "region": os.environ.get("AWS_REGION", "us-east-1"),
            }
        else:
            credentials = {"region": os.environ.get("AWS_REGION", "us-east-1")}

    elif provider == Provider.AZURE:
        credentials = {
            "azure_tenant_id": os.environ["AZURE_TENANT_ID"],
            "subscription_id": os.environ["AZURE_SUBSCRIPTION_ID"],
            "client_id": os.environ["AZURE_CLIENT_ID"],
            "client_secret": os.environ["AZURE_CLIENT_SECRET"],
        }

    elif provider == Provider.GCP:
        import json
        sa_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        sa_info = None
        if sa_path:
            with open(sa_path) as f:
                sa_info = json.load(f)
        credentials = {
            "project_id": os.environ["GCP_PROJECT_ID"],
            "service_account_info": sa_info,
        }

    elif provider == Provider.GITHUB:
        credentials = {
            "github_token": os.environ["GITHUB_TOKEN"],
            "org_name": os.environ["GITHUB_ORG"],
        }

    return cls(ConnectorConfig(tenant_id=tenant_id, provider=provider, credentials=credentials))


async def _push_results(results: list[ScanResult], client: httpx.AsyncClient) -> None:
    """Send scan results to the control plane."""
    for result in results:
        if result.error:
            log.warning("Scan error for %s: %s", result.provider, result.error)
            continue

        payload = result.model_dump(mode="json")
        resp = await client.post(
            f"{CONTROL_PLANE_URL}/v1/internal/scan-results",
            json=payload,
            headers={"Authorization": f"Bearer {SENSOR_TOKEN}"},
            timeout=30.0,
        )
        if resp.status_code >= 400:
            log.error("Failed to push %s results: %s", result.provider, resp.text)
        else:
            log.info("Pushed %d identities for %s", len(result.identities), result.provider)


async def run_scan_cycle() -> None:
    """Run one full scan cycle across all configured providers."""
    providers = [p.strip() for p in os.environ.get("ENABLED_PROVIDERS", "AWS,AZURE,GCP,GITHUB").split(",")]
    connectors = []
    for provider in providers:
        connector = _build_connector(provider, TENANT_ID)
        if connector:
            connectors.append(connector)
        else:
            log.warning("No connector found for provider: %s", provider)

    log.info("Starting scan cycle for %d providers", len(connectors))
    results = await asyncio.gather(*[c.scan() for c in connectors], return_exceptions=False)

    async with httpx.AsyncClient() as client:
        await _push_results(list(results), client)

    log.info("Scan cycle complete")


async def main() -> None:
    interval_seconds = int(os.environ.get("SCAN_INTERVAL_SECONDS", str(4 * 3600)))
    log.info("Sensor started. Scan interval: %ds. Tenant: %s", interval_seconds, TENANT_ID)

    while True:
        try:
            await run_scan_cycle()
        except Exception as exc:
            log.exception("Scan cycle failed: %s", exc)
        await asyncio.sleep(interval_seconds)


if __name__ == "__main__":
    asyncio.run(main())
