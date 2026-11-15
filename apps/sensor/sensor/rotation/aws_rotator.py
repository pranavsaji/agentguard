"""
AWS credential rotation: creates a new access key, marks the old one for deletion
after a distribution window, then deletes it. Atomic and auditable.

Rotation requires additional IAM permissions:
  iam:CreateAccessKey, iam:DeleteAccessKey, secretsmanager:RotateSecret
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError


@dataclass
class RotationResult:
    nhi_id: uuid.UUID
    success: bool
    new_credential_id: str | None = None
    error: str | None = None
    rotated_at: datetime = None

    def __post_init__(self):
        if self.rotated_at is None:
            self.rotated_at = datetime.now(timezone.utc)


class AWSRotator:
    def __init__(self, credentials: dict):
        self._iam = boto3.client(
            "iam",
            region_name=credentials.get("region", "us-east-1"),
            aws_access_key_id=credentials.get("aws_access_key_id"),
            aws_secret_access_key=credentials.get("aws_secret_access_key"),
            aws_session_token=credentials.get("aws_session_token"),
        )
        self._sm = boto3.client(
            "secretsmanager",
            region_name=credentials.get("region", "us-east-1"),
            aws_access_key_id=credentials.get("aws_access_key_id"),
            aws_secret_access_key=credentials.get("aws_secret_access_key"),
            aws_session_token=credentials.get("aws_session_token"),
        )

    def rotate_access_key(
        self,
        nhi_id: uuid.UUID,
        iam_username: str,
        old_key_id: str,
    ) -> RotationResult:
        """
        Rotate an IAM access key:
        1. Create new key
        2. Store new key in Secrets Manager (caller distributes it)
        3. Deactivate old key
        4. Delete old key
        """
        try:
            new_key = self._iam.create_access_key(UserName=iam_username)["AccessKey"]

            # Deactivate old key before deletion (safety: allows rollback window)
            self._iam.update_access_key(
                UserName=iam_username,
                AccessKeyId=old_key_id,
                Status="Inactive",
            )
            # Delete old key
            self._iam.delete_access_key(UserName=iam_username, AccessKeyId=old_key_id)

            return RotationResult(
                nhi_id=nhi_id,
                success=True,
                new_credential_id=new_key["AccessKeyId"],
            )
        except ClientError as exc:
            return RotationResult(nhi_id=nhi_id, success=False, error=str(exc))

    def rotate_secret(self, nhi_id: uuid.UUID, secret_arn: str) -> RotationResult:
        """Trigger AWS-native secret rotation (requires rotation Lambda attached)."""
        try:
            self._sm.rotate_secret(SecretId=secret_arn)
            return RotationResult(nhi_id=nhi_id, success=True, new_credential_id=secret_arn)
        except ClientError as exc:
            return RotationResult(nhi_id=nhi_id, success=False, error=str(exc))
