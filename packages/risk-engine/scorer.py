"""
Risk scoring engine. Aggregates factor contributions into a final 0-100 score
with full explainability. Deterministic and auditable — no black boxes.
"""
from __future__ import annotations

from datetime import datetime

from nhi_schema.models import NHIIdentity, RiskFactor, RiskScore

from .factors import (
    FactorResult,
    factor_blast_radius,
    factor_credential_age,
    factor_exposure_surface,
    factor_over_permission,
    factor_staleness,
)


def compute_risk_score(
    identity: NHIIdentity,
    *,
    granted_count: int = 0,
    used_count: int = 0,
    reachable_services: int = 1,
    privilege_level: str = "standard",
    account_scope: str = "single",
    max_age_days: int = 90,
    stale_threshold_days: int = 30,
) -> RiskScore:
    """
    Compute a deterministic, explainable risk score for a single NHI.
    All inputs beyond the identity itself come from the cloud connector's permission analysis.
    """
    factor_results: list[FactorResult] = [
        factor_over_permission(granted_count, used_count),
        factor_credential_age(identity.last_rotated_at, max_age_days),
        factor_staleness(identity.last_used_at, stale_threshold_days),
        factor_exposure_surface(reachable_services),
        factor_blast_radius(privilege_level, account_scope),
    ]

    total = sum(f.contribution for f in factor_results)
    score = round(min(100.0, max(0.0, total)), 2)

    return RiskScore(
        score=score,
        severity=RiskScore.severity_from_score(score),
        computed_at=datetime.utcnow(),
        factors=[
            RiskFactor(
                name=f.name,
                weight=f.weight,
                raw_value=f.raw_value,
                contribution=f.contribution,
                remediation=f.remediation,
            )
            for f in factor_results
        ],
    )


def batch_score(
    identities: list[NHIIdentity],
    context_map: dict[str, dict],
) -> list[NHIIdentity]:
    """
    Score a list of identities using pre-fetched context (permissions, usage stats).
    context_map keys are identity.external_id.
    Returns identities with risk_score populated.
    """
    scored = []
    for identity in identities:
        ctx = context_map.get(identity.external_id, {})
        identity.risk_score = compute_risk_score(identity, **ctx)
        scored.append(identity)
    return scored
