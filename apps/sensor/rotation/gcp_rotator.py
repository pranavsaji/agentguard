"""
GCP service account key rotation: creates a new key, disables the old one,
then deletes it after the distribution window.
"""
from __future__ import annotations

import uuid

from google.cloud import iam_admin_v1
from google.oauth2 import service_account

from sensor.rotation.aws_rotator import RotationResult


class GCPRotator:
    def __init__(self, credentials: dict):
        sa_info = credentials.get("service_account_info")
        google_creds = (
            service_account.Credentials.from_service_account_info(sa_info)
            if sa_info else None
        )
        self._iam = iam_admin_v1.IAMClient(credentials=google_creds)
        self._project_id = credentials["project_id"]

    def rotate_service_account_key(
        self,
        nhi_id: uuid.UUID,
        sa_email: str,
        old_key_name: str,
    ) -> RotationResult:
        """
        Create a new service account key and delete the old one.
        Returns the new key's JSON bytes in new_credential_id (base64 encoded).
        """
        try:
            sa_name = f"projects/{self._project_id}/serviceAccounts/{sa_email}"

            # Create new key
            create_req = iam_admin_v1.CreateServiceAccountKeyRequest(name=sa_name)
            new_key = self._iam.create_service_account_key(request=create_req)

            # Disable old key
            disable_req = iam_admin_v1.DisableServiceAccountKeyRequest(name=old_key_name)
            self._iam.disable_service_account_key(request=disable_req)

            # Delete old key
            delete_req = iam_admin_v1.DeleteServiceAccountKeyRequest(name=old_key_name)
            self._iam.delete_service_account_key(request=delete_req)

            import base64
            new_key_b64 = base64.b64encode(new_key.private_key_data).decode()
            return RotationResult(nhi_id=nhi_id, success=True, new_credential_id=new_key.name)
        except Exception as exc:
            return RotationResult(nhi_id=nhi_id, success=False, error=str(exc))
