"""
Risk factor definitions and weight configuration.
Each factor contributes a weighted score toward the final 0-100 NHI risk score.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class FactorResult:
    name: str
    weight: float
    raw_value: float       # normalized 0.0–1.0
    contribution: float    # weight * raw_value * 100
    remediation: str | None = None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def factor_over_permission(granted_count: int, used_count: int) -> FactorResult:
    """30% weight: ratio of unused granted permissions."""
    weight = 0.30
    if granted_count == 0:
        raw = 0.0
        remediation = None
    elif used_count == 0:
        raw = 1.0
        remediation = "All permissions unused — revoke or scope to minimum required."
    else:
        raw = min(1.0, (granted_count - used_count) / granted_count)
        if raw > 0.5:
            remediation = f"Only {used_count}/{granted_count} permissions used — apply least-privilege policy."
        else:
            remediation = None
    return FactorResult(
        name="over_permission_ratio",
        weight=weight,
        raw_value=raw,
        contribution=round(weight * raw * 100, 2),
        remediation=remediation,
    )


def factor_credential_age(last_rotated_at: datetime | None, max_age_days: int = 90) -> FactorResult:
    """20% weight: days since last rotation vs. policy maximum."""
    weight = 0.20
    if last_rotated_at is None:
        raw = 1.0
        remediation = "Credential has never been rotated — rotate immediately."
    else:
        last_rotated_at = last_rotated_at.replace(tzinfo=timezone.utc) if last_rotated_at.tzinfo is None else last_rotated_at
        age_days = (_now() - last_rotated_at).days
        raw = min(1.0, age_days / max_age_days)
        if raw >= 1.0:
            remediation = f"Credential is {age_days}d old (max {max_age_days}d) — rotate now."
        else:
            remediation = None
    return FactorResult(
        name="credential_age",
        weight=weight,
        raw_value=raw,
        contribution=round(weight * raw * 100, 2),
        remediation=remediation,
    )


def factor_staleness(last_used_at: datetime | None, stale_threshold_days: int = 30) -> FactorResult:
    """20% weight: days since last use (never used = max risk)."""
    weight = 0.20
    if last_used_at is None:
        raw = 1.0
        remediation = "Credential has never been used — candidate for immediate revocation."
    else:
        last_used_at = last_used_at.replace(tzinfo=timezone.utc) if last_used_at.tzinfo is None else last_used_at
        idle_days = (_now() - last_used_at).days
        raw = min(1.0, idle_days / stale_threshold_days)
        if raw >= 1.0:
            remediation = f"Unused for {idle_days}d — review and revoke if no longer needed."
        else:
            remediation = None
    return FactorResult(
        name="staleness",
        weight=weight,
        raw_value=raw,
        contribution=round(weight * raw * 100, 2),
        remediation=remediation,
    )


def factor_exposure_surface(reachable_service_count: int, max_expected: int = 10) -> FactorResult:
    """15% weight: number of distinct services/APIs this credential can reach."""
    weight = 0.15
    raw = min(1.0, reachable_service_count / max(1, max_expected))
    remediation = (
        f"Credential can reach {reachable_service_count} services — scope to required services only."
        if reachable_service_count > max_expected else None
    )
    return FactorResult(
        name="exposure_surface",
        weight=weight,
        raw_value=raw,
        contribution=round(weight * raw * 100, 2),
        remediation=remediation,
    )


# Privilege levels mapped to 0.0–1.0 blast radius scores
PRIVILEGE_LEVELS: dict[str, float] = {
    "none": 0.0,
    "readonly": 0.1,
    "limited": 0.3,
    "standard": 0.5,
    "elevated": 0.7,
    "admin": 0.9,
    "superadmin": 1.0,
}


def factor_blast_radius(privilege_level: str, account_scope: str = "single") -> FactorResult:
    """15% weight: privilege level × account scope multiplier."""
    weight = 0.15
    scope_multiplier = {"single": 0.5, "multi": 0.75, "organization": 1.0}.get(account_scope, 0.5)
    privilege_raw = PRIVILEGE_LEVELS.get(privilege_level.lower(), 0.5)
    raw = min(1.0, privilege_raw * scope_multiplier)
    remediation = (
        f"{privilege_level} privilege across {account_scope} scope — review necessity of elevated access."
        if raw > 0.5 else None
    )
    return FactorResult(
        name="blast_radius",
        weight=weight,
        raw_value=raw,
        contribution=round(weight * raw * 100, 2),
        remediation=remediation,
    )
