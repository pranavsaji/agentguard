"""
Azure credential rotation: rotates app registration client secrets
and Key Vault secrets.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timedelta, timezone

from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from msgraph import GraphServiceClient
from msgraph.generated.applications.item.add_password.add_password_post_request_body import (
    AddPasswordPostRequestBody,
)
from msgraph.generated.applications.item.remove_password.remove_password_post_request_body import (
    RemovePasswordPostRequestBody,
)
from msgraph.generated.models.password_credential import PasswordCredential

from sensor.rotation.aws_rotator import RotationResult


class AzureRotator:
    def __init__(self, credentials: dict):
        self._creds = ClientSecretCredential(
            tenant_id=credentials["azure_tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
        )
        self._subscription_id = credentials["subscription_id"]

    def rotate_app_secret(
        self,
        nhi_id: uuid.UUID,
        app_object_id: str,
        old_key_id: str,
        display_name: str = "AgentGuard-rotated",
        validity_days: int = 365,
    ) -> RotationResult:
        """Add a new client secret to the app registration, then remove the old one.

        Uses Microsoft Graph (the Azure AD Graph API behind azure-mgmt-graphrbac
        has been retired). The new secret is created before the old one is
        removed, so the application is never left without a valid credential.
        """
        try:
            new_key_id = asyncio.run(
                self._rotate_app_secret(app_object_id, old_key_id, display_name, validity_days)
            )
            return RotationResult(nhi_id=nhi_id, success=True, new_credential_id=new_key_id)
        except Exception as exc:
            return RotationResult(nhi_id=nhi_id, success=False, error=str(exc))

    async def _rotate_app_secret(
        self, app_object_id: str, old_key_id: str, display_name: str, validity_days: int
    ) -> str:
        graph = GraphServiceClient(credentials=self._creds)
        app = graph.applications.by_application_id(app_object_id)
        now = datetime.now(timezone.utc)
        created = await app.add_password.post(
            AddPasswordPostRequestBody(
                password_credential=PasswordCredential(
                    display_name=display_name,
                    start_date_time=now,
                    end_date_time=now + timedelta(days=validity_days),
                )
            )
        )
        if created is None or created.key_id is None:
            raise RuntimeError("Microsoft Graph did not return the new credential")
        await app.remove_password.post(RemovePasswordPostRequestBody(key_id=uuid.UUID(old_key_id)))
        return str(created.key_id)

    def rotate_keyvault_secret(
        self,
        nhi_id: uuid.UUID,
        vault_url: str,
        secret_name: str,
        new_value: str,
    ) -> RotationResult:
        """Set a new version of a Key Vault secret."""
        try:
            client = SecretClient(vault_url=vault_url, credential=self._creds)
            client.set_secret(secret_name, new_value)
            return RotationResult(nhi_id=nhi_id, success=True, new_credential_id=secret_name)
        except Exception as exc:
            return RotationResult(nhi_id=nhi_id, success=False, error=str(exc))
