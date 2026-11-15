"""
GCP IAM + Secret Manager scanner.
Enumerates service accounts, service account keys, and Secret Manager secrets.

Required roles (grant to the AgentGuard service account):
  roles/iam.securityReviewer
  roles/secretmanager.viewer
  roles/cloudasset.viewer
"""
from __future__ import annotations

import uuid

from google.cloud import iam_admin_v1, secretmanager_v1
from google.oauth2 import service_account

from nhi_schema.models import NHIIdentity, NHIStatus, NHIType, Provider

from ..base import BaseConnector, ConnectorConfig
from ..utils import classify_by_name, to_utc


class GCPIAMScanner(BaseConnector):
    provider = Provider.GCP

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        creds = config.credentials
        self._project_id = creds["project_id"]

        sa_info = creds.get("service_account_info")
        google_creds = (
            service_account.Credentials.from_service_account_info(sa_info)
            if sa_info else None
        )
        self._iam_client = iam_admin_v1.IAMClient(credentials=google_creds)
        self._sm_client = secretmanager_v1.SecretManagerServiceClient(credentials=google_creds)

    async def _scan(self) -> list[NHIIdentity]:
        identities: list[NHIIdentity] = []
        identities.extend(await self._scan_service_accounts())
        identities.extend(await self._scan_secret_manager())
        return identities

    async def _scan_service_accounts(self) -> list[NHIIdentity]:
        def _list_sas():
            request = iam_admin_v1.ListServiceAccountsRequest(
                name=f"projects/{self._project_id}"
            )
            return list(self._iam_client.list_service_accounts(request=request))

        service_accounts = await self._run_in_executor(_list_sas)
        identities = []

        for sa in service_accounts:
            # Skip Google-managed service accounts
            if sa.email.endswith(".gserviceaccount.com") and "iam.gserviceaccount.com" not in sa.email:
                pass  # customer SA — include it

            def _list_keys(sa_name=sa.name):
                req = iam_admin_v1.ListServiceAccountKeysRequest(name=sa_name)
                return self._iam_client.list_service_account_keys(request=req).keys

            keys = await self._run_in_executor(_list_keys)

            for key in keys:
                # GCP key types: USER_MANAGED (customer keys) vs SYSTEM_MANAGED
                if key.key_type.name != "USER_MANAGED":
                    continue

                identities.append(
                    NHIIdentity(
                        id=uuid.uuid4(),
                        tenant_id=self.tenant_id,
                        external_id=key.name,
                        name=f"{sa.display_name or sa.email} / {key.name.split('/')[-1][:12]}",
                        type=NHIType.API_KEY,
                        provider=Provider.GCP,
                        classification=classify_by_name(sa.display_name or sa.email),
                        created_at=to_utc(key.valid_after_time),
                        status=NHIStatus.ACTIVE if not key.disabled else NHIStatus.REVOKED,
                        raw_metadata={
                            "sa_email": sa.email,
                            "sa_name": sa.name,
                            "key_name": key.name,
                            "key_algorithm": key.key_algorithm.name,
                            "valid_before": str(key.valid_before_time),
                            "project_id": self._project_id,
                        },
                    )
                )

            # Also emit the service account itself as a SERVICE_ACCOUNT identity
            identities.append(
                NHIIdentity(
                    id=uuid.uuid4(),
                    tenant_id=self.tenant_id,
                    external_id=sa.unique_id,
                    name=sa.display_name or sa.email,
                    type=NHIType.SERVICE_ACCOUNT,
                    provider=Provider.GCP,
                    classification=classify_by_name(sa.display_name or sa.email),
                    status=NHIStatus.ACTIVE if sa.disabled is False else NHIStatus.REVOKED,
                    raw_metadata={
                        "email": sa.email,
                        "unique_id": sa.unique_id,
                        "project_id": self._project_id,
                        "description": sa.description,
                    },
                )
            )

        return identities

    async def _scan_secret_manager(self) -> list[NHIIdentity]:
        def _list_secrets():
            parent = f"projects/{self._project_id}"
            return list(self._sm_client.list_secrets(request={"parent": parent}))

        try:
            secrets = await self._run_in_executor(_list_secrets)
        except Exception:
            return []

        identities = []
        for secret in secrets:
            labels = dict(secret.labels) if secret.labels else {}
            create_time = to_utc(secret.create_time) if hasattr(secret, "create_time") else None

            identities.append(
                NHIIdentity(
                    id=uuid.uuid4(),
                    tenant_id=self.tenant_id,
                    external_id=secret.name,
                    name=secret.name.split("/")[-1],
                    type=NHIType.API_KEY,
                    provider=Provider.GCP,
                    classification=classify_by_name(secret.name.split("/")[-1]),
                    created_at=create_time,
                    raw_metadata={
                        "secret_name": secret.name,
                        "project_id": self._project_id,
                        "labels": labels,
                        "replication": str(secret.replication),
                    },
                )
            )
        return identities
