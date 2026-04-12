"""
Abstract base connector. All cloud scanner implementations inherit from this.
The contract: scan() always returns a ScanResult with normalized NHIIdentity objects.
Scans are stateless and idempotent — running twice produces the same output.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from abc import ABC, abstractmethod
from typing import Any

from nhi_schema.models import NHIIdentity, Provider, ScanResult


class ConnectorConfig:
    """Provider-specific credentials and config, passed at construction time."""

    def __init__(self, tenant_id: uuid.UUID, provider: Provider, credentials: dict[str, Any]):
        self.tenant_id = tenant_id
        self.provider = provider
        self.credentials = credentials


class BaseConnector(ABC):
    """
    Abstract base for all cloud identity scanners.
    Subclasses implement _scan() and optionally _enrich().
    """

    provider: Provider  # Must be set on the class

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.tenant_id = config.tenant_id

    async def scan(self) -> ScanResult:
        """
        Execute a full scan and return normalized NHIIdentity objects.
        Wraps _scan() with timing and error capture.
        """
        start = time.monotonic()
        try:
            identities = await self._scan()
            enriched = await self._enrich(identities)
            return ScanResult(
                provider=self.provider,
                tenant_id=self.tenant_id,
                identities=enriched,
                duration_seconds=round(time.monotonic() - start, 3),
            )
        except Exception as exc:
            return ScanResult(
                provider=self.provider,
                tenant_id=self.tenant_id,
                identities=[],
                error=str(exc),
                duration_seconds=round(time.monotonic() - start, 3),
            )

    @abstractmethod
    async def _scan(self) -> list[NHIIdentity]:
        """Return raw normalized identities from the provider API."""
        ...

    async def _enrich(self, identities: list[NHIIdentity]) -> list[NHIIdentity]:
        """
        Optional post-scan enrichment (e.g. cross-referencing last-used from audit logs).
        Default implementation is a no-op.
        """
        return identities

    @staticmethod
    async def _run_in_executor(fn, *args) -> Any:
        """Run a synchronous (boto3/azure-sdk) call in a thread pool to avoid blocking."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, fn, *args)
