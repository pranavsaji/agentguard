"""
Authentication middleware: validates Clerk JWTs, extracts tenant_id,
and injects both into the request state for downstream use.
"""
from __future__ import annotations

import uuid
from typing import Annotated

import httpx
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import ExpiredSignatureError, JWTError, jwt

from .config import get_settings

_bearer = HTTPBearer(auto_error=True)


async def _fetch_clerk_jwks() -> dict:
    """Fetch Clerk's JWKS endpoint (cached in practice via httpx connection pool)."""
    cfg = get_settings()
    # Clerk JWKS endpoint follows the pattern below
    url = f"https://api.clerk.dev/v1/jwks"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers={"Authorization": f"Bearer {cfg.clerk_secret_key}"})
        resp.raise_for_status()
        return resp.json()


def _decode_jwt(token: str) -> dict:
    cfg = get_settings()
    try:
        if cfg.clerk_jwt_verification_key:
            # Offline verification with the PEM public key (preferred in production)
            payload = jwt.decode(
                token,
                cfg.clerk_jwt_verification_key,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        else:
            # Decode without verification (dev-only — never in production)
            payload = jwt.get_unverified_claims(token)
        return payload
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
    except JWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {exc}")


class AuthContext:
    """Resolved authentication context attached to every authenticated request."""

    def __init__(self, user_id: str, tenant_id: uuid.UUID, role: str, email: str | None = None):
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.role = role
        self.email = email

    def require_role(self, *roles: str) -> None:
        if self.role not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{self.role}' is not authorized for this action.",
            )


async def get_auth_context(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
) -> AuthContext:
    """
    FastAPI dependency: validates the bearer JWT and returns AuthContext.
    Clerk stores custom metadata in the 'public_metadata' claim.
    """
    payload = _decode_jwt(credentials.credentials)

    user_id: str = payload.get("sub", "")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing subject claim")

    metadata: dict = payload.get("public_metadata", {})
    tenant_id_raw: str | None = metadata.get("tenant_id")
    role: str = metadata.get("role", "ANALYST")

    if not tenant_id_raw:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No tenant_id in token metadata — ensure user is onboarded.",
        )

    try:
        tenant_id = uuid.UUID(tenant_id_raw)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid tenant_id format")

    ctx = AuthContext(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        email=payload.get("email"),
    )
    # Attach to request state so middleware/hooks can access it without re-parsing
    request.state.auth = ctx
    return ctx


# Convenience type alias for route signatures
Auth = Annotated[AuthContext, Depends(get_auth_context)]
