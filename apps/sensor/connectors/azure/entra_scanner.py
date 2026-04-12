"""
Azure Entra ID (formerly Azure AD) + Key Vault scanner.
Enumerates service principals, app registrations, managed identities,
and Key Vault secrets.

Required permissions (reader role on the subscription + Key Vault reader):
  Microsoft.Graph: Application.Read.All, ServicePrincipalEndpoint.Read.All
  Microsoft.KeyVault: Microsoft.KeyVault/vaults/read, secrets/read
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from azure.identity import ClientSecretCredential
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.mgmt.resource import ResourceManagementClient
from msgraph import GraphServiceClient

from nhi_schema.models import Classification, NHIIdentity, NHIStatus, NHIType, Provider

from ..base import BaseConnector, ConnectorConfig
from ..utils import classify_by_name, to_utc


class AzureEntraScanner(BaseConnector):
    provider = Provider.AZURE

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        creds = config.credentials
        self._tenant_azure = creds["azure_tenant_id"]
        self._subscription_id = creds["subscription_id"]
        self._credential = ClientSecretCredential(
            tenant_id=self._tenant_azure,
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )
        self._graph = GraphServiceClient(credentials=self._credential)
        self._kv_mgmt = KeyVaultManagementClient(self._credential, self._subscription_id)

    async def _scan(self) -> list[NHIIdentity]:
        identities: list[NHIIdentity] = []
        identities.extend(await self._scan_service_principals())
        identities.extend(await self._scan_app_registrations())
        identities.extend(await self._scan_key_vaults())
        return identities

    async def _scan_service_principals(self) -> list[NHIIdentity]:
        identities = []
        result = await self._graph.service_principals.get()
        sps = result.value or []

        for sp in sps:
            # Skip first-party Microsoft service principals
            if sp.app_owner_organization_id and str(sp.app_owner_organization_id) == "f8cdef31-a31e-4b4a-93e4-5f571e91255a":
                continue

            identities.append(
                NHIIdentity(
                    id=uuid.uuid4(),
                    tenant_id=self.tenant_id,
                    external_id=str(sp.id),
                    name=sp.display_name or str(sp.id),
                    type=NHIType.SERVICE_ACCOUNT,
                    provider=Provider.AZURE,
                    classification=classify_by_name(sp.display_name or ""),
                    created_at=to_utc(sp.created_date_time),
                    status=NHIStatus.ACTIVE if sp.account_enabled else NHIStatus.REVOKED,
                    raw_metadata={
                        "object_id": str(sp.id),
                        "app_id": str(sp.app_id),
                        "service_principal_type": sp.service_principal_type,
                        "sign_in_audience": sp.sign_in_audience,
                        "tags": sp.tags or [],
                    },
                )
            )
        return identities

    async def _scan_app_registrations(self) -> list[NHIIdentity]:
        identities = []
        result = await self._graph.applications.get()
        apps = result.value or []

        for app in apps:
            # Each app credential (client secret / certificate) is a distinct NHI
            for cred in app.password_credentials or []:
                identities.append(
                    NHIIdentity(
                        id=uuid.uuid4(),
                        tenant_id=self.tenant_id,
                        external_id=f"{app.id}/{cred.key_id}",
                        name=f"{app.display_name} / {cred.display_name or cred.key_id}",
                        type=NHIType.OAUTH_TOKEN,
                        provider=Provider.AZURE,
                        classification=classify_by_name(app.display_name or ""),
                        created_at=to_utc(cred.start_date_time),
                        last_rotated_at=to_utc(cred.start_date_time),
                        raw_metadata={
                            "app_id": str(app.app_id),
                            "app_object_id": str(app.id),
                            "credential_key_id": str(cred.key_id),
                            "expiry": str(cred.end_date_time),
                            "hint": cred.hint,
                        },
                    )
                )
        return identities

    async def _scan_key_vaults(self) -> list[NHIIdentity]:
        identities = []

        def _list_vaults():
            return list(self._kv_mgmt.vaults.list())

        vaults = await self._run_in_executor(_list_vaults)

        for vault in vaults:
            identities.append(
                NHIIdentity(
                    id=uuid.uuid4(),
                    tenant_id=self.tenant_id,
                    external_id=vault.id,
                    name=vault.name,
                    type=NHIType.API_KEY,
                    provider=Provider.AZURE,
                    classification=Classification.INTEGRATION,
                    raw_metadata={
                        "vault_uri": vault.properties.vault_uri if vault.properties else None,
                        "location": vault.location,
                        "resource_group": vault.id.split("/")[4] if vault.id else None,
                        "sku": str(vault.properties.sku.name) if vault.properties and vault.properties.sku else None,
                    },
                )
            )
        return identities
