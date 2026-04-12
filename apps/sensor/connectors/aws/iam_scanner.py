"""
AWS IAM + Secrets Manager scanner.
Enumerates IAM users, roles, access keys, and Secrets Manager secrets,
then normalizes them to the canonical NHIIdentity schema.

Required IAM permissions:
  iam:List*, iam:Get*, iam:GenerateCredentialReport
  secretsmanager:ListSecrets, secretsmanager:DescribeSecret
  organizations:ListAccounts (for org-wide scans)
  cloudtrail:LookupEvents
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from nhi_schema.models import Classification, NHIIdentity, NHIStatus, NHIType, Provider

from ..base import BaseConnector, ConnectorConfig
from ..utils import classify_by_name, infer_privilege_from_policies, to_utc


class AWSIAMScanner(BaseConnector):
    provider = Provider.AWS

    def __init__(self, config: ConnectorConfig):
        super().__init__(config)
        creds = config.credentials
        self._iam = boto3.client(
            "iam",
            region_name=creds.get("region", "us-east-1"),
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key"),
            aws_session_token=creds.get("aws_session_token"),
        )
        self._sm = boto3.client(
            "secretsmanager",
            region_name=creds.get("region", "us-east-1"),
            aws_access_key_id=creds.get("aws_access_key_id"),
            aws_secret_access_key=creds.get("aws_secret_access_key"),
            aws_session_token=creds.get("aws_session_token"),
        )

    async def _scan(self) -> list[NHIIdentity]:
        identities: list[NHIIdentity] = []
        identities.extend(await self._scan_iam_users())
        identities.extend(await self._scan_iam_roles())
        identities.extend(await self._scan_secrets_manager())
        return identities

    async def _scan_iam_users(self) -> list[NHIIdentity]:
        def _list_users():
            paginator = self._iam.get_paginator("list_users")
            return [u for page in paginator.paginate() for u in page["Users"]]

        users = await self._run_in_executor(_list_users)
        identities = []

        for user in users:
            # Get access keys for each user
            def _list_keys(username=user["UserName"]):
                return self._iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

            keys = await self._run_in_executor(_list_keys)

            for key in keys:
                def _last_used(key_id=key["AccessKeyId"]):
                    return self._iam.get_access_key_last_used(AccessKeyId=key_id)

                last_used_info = await self._run_in_executor(_last_used)
                last_used_at = to_utc(last_used_info.get("AccessKeyLastUsed", {}).get("LastUsedDate"))

                # Get attached policies to assess privilege level
                def _policies(username=user["UserName"]):
                    attached = self._iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
                    inline = self._iam.list_user_policies(UserName=username)["PolicyNames"]
                    return [p["PolicyName"] for p in attached] + inline

                policy_names = await self._run_in_executor(_policies)
                privilege = infer_privilege_from_policies(policy_names)

                status = (
                    NHIStatus.ACTIVE if key["Status"] == "Active"
                    else NHIStatus.REVOKED
                )

                identities.append(
                    NHIIdentity(
                        id=uuid.uuid4(),
                        tenant_id=self.tenant_id,
                        external_id=key["AccessKeyId"],
                        name=f"{user['UserName']}/{key['AccessKeyId'][:8]}",
                        type=NHIType.API_KEY,
                        provider=Provider.AWS,
                        classification=classify_by_name(user["UserName"]),
                        created_at=to_utc(key.get("CreateDate")),
                        last_used_at=last_used_at,
                        status=status,
                        raw_metadata={
                            "iam_user": user["UserName"],
                            "arn": user["Arn"],
                            "access_key_id": key["AccessKeyId"],
                            "key_status": key["Status"],
                            "policies": policy_names,
                            "privilege_level": privilege,
                        },
                    )
                )

        return identities

    async def _scan_iam_roles(self) -> list[NHIIdentity]:
        def _list_roles():
            paginator = self._iam.get_paginator("list_roles")
            return [r for page in paginator.paginate() for r in page["Roles"]]

        roles = await self._run_in_executor(_list_roles)
        identities = []

        for role in roles:
            # Skip AWS service-linked roles — not customer-managed
            if ":aws-service-role/" in role.get("Path", ""):
                continue

            def _attached(role_name=role["RoleName"]):
                return self._iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]

            policies = await self._run_in_executor(_attached)
            privilege = infer_privilege_from_policies([p["PolicyName"] for p in policies])

            identities.append(
                NHIIdentity(
                    id=uuid.uuid4(),
                    tenant_id=self.tenant_id,
                    external_id=role["RoleId"],
                    name=role["RoleName"],
                    type=NHIType.SERVICE_ACCOUNT,
                    provider=Provider.AWS,
                    classification=classify_by_name(role["RoleName"]),
                    created_at=to_utc(role.get("CreateDate")),
                    raw_metadata={
                        "arn": role["Arn"],
                        "path": role["Path"],
                        "assume_role_policy": str(role.get("AssumeRolePolicyDocument", {})),
                        "attached_policies": [p["PolicyName"] for p in policies],
                        "privilege_level": privilege,
                    },
                )
            )

        return identities

    async def _scan_secrets_manager(self) -> list[NHIIdentity]:
        def _list_secrets():
            paginator = self._sm.get_paginator("list_secrets")
            return [s for page in paginator.paginate() for s in page["SecretList"]]

        try:
            secrets = await self._run_in_executor(_list_secrets)
        except ClientError:
            return []

        identities = []
        for secret in secrets:
            last_rotated = to_utc(secret.get("LastRotatedDate"))
            last_accessed = to_utc(secret.get("LastAccessedDate"))

            identities.append(
                NHIIdentity(
                    id=uuid.uuid4(),
                    tenant_id=self.tenant_id,
                    external_id=secret["ARN"],
                    name=secret["Name"],
                    type=NHIType.API_KEY,
                    provider=Provider.AWS,
                    classification=classify_by_name(secret["Name"]),
                    created_at=to_utc(secret.get("CreatedDate")),
                    last_used_at=last_accessed,
                    last_rotated_at=last_rotated,
                    raw_metadata={
                        "arn": secret["ARN"],
                        "rotation_enabled": secret.get("RotationEnabled", False),
                        "rotation_rules": secret.get("RotationRules", {}),
                        "tags": {t["Key"]: t["Value"] for t in secret.get("Tags", [])},
                    },
                )
            )

        return identities
