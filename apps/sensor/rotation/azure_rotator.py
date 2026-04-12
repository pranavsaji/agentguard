"""
Azure credential rotation: rotates app registration client secrets
and Key Vault secrets.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from azure.identity import ClientSecretCredential
from azure.mgmt.graphrbac import GraphRbacManagementClient
from azure.keyvault.secrets import SecretClient

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
        """Add a new client secret to the app registration, remove the old one."""
        from azure.graphrbac.models import PasswordCredential
        try:
            client = GraphRbacManagementClient(self._creds, self._subscription_id)
            now = datetime.now(timezone.utc)
            new_cred = PasswordCredential(
                start_date=now,
                end_date=now + timedelta(days=validity_days),
                custom_key_identifier=display_name.encode(),
            )
            app = client.applications.get(app_object_id)
            existing = [c for c in (app.password_credentials or []) if str(c.key_id) != old_key_id]
            existing.append(new_cred)
            client.applications.patch(app_object_id, {"passwordCredentials": existing})

            return RotationResult(nhi_id=nhi_id, success=True, new_credential_id=display_name)
        except Exception as exc:
            return RotationResult(nhi_id=nhi_id, success=False, error=str(exc))

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
