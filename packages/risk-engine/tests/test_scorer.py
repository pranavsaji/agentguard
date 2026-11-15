"""Unit tests for the deterministic NHI risk engine.

These pin down the scoring contract: factor weights, normalization,
clamping, severity bands, and remediation hints.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from nhi_schema.models import NHIIdentity, NHIType, Provider, RiskScore
from risk_engine import batch_score, compute_risk_score
from risk_engine.factors import (
    factor_blast_radius,
    factor_credential_age,
    factor_exposure_surface,
    factor_over_permission,
    factor_staleness,
)

NOW = datetime.now(timezone.utc)


def make_identity(**overrides) -> NHIIdentity:
    fields = dict(
        tenant_id=uuid.uuid4(),
        external_id="key-1",
        name="ci-deploy-key",
        type=NHIType.API_KEY,
        provider=Provider.AWS,
    )
    fields.update(overrides)
    return NHIIdentity(**fields)


# ---------------------------------------------------------------- weights

def test_factor_weights_sum_to_one():
    results = [
        factor_over_permission(10, 5),
        factor_credential_age(NOW, 90),
        factor_staleness(NOW, 30),
        factor_exposure_surface(1),
        factor_blast_radius("standard"),
    ]
    assert sum(r.weight for r in results) == pytest.approx(1.0)


# ---------------------------------------------------------- over-permission

def test_over_permission_no_grants_is_zero_risk():
    r = factor_over_permission(0, 0)
    assert r.raw_value == 0.0 and r.contribution == 0.0 and r.remediation is None


def test_over_permission_all_unused_is_max_risk():
    r = factor_over_permission(12, 0)
    assert r.raw_value == 1.0
    assert r.contribution == pytest.approx(30.0)
    assert "revoke" in r.remediation


def test_over_permission_partial_use_is_proportional():
    r = factor_over_permission(10, 2)
    assert r.raw_value == pytest.approx(0.8)
    assert r.contribution == pytest.approx(24.0)
    assert "2/10" in r.remediation


def test_over_permission_mostly_used_has_no_remediation():
    r = factor_over_permission(10, 8)
    assert r.raw_value == pytest.approx(0.2)
    assert r.remediation is None


# ----------------------------------------------------------- credential age

def test_never_rotated_is_max_age_risk():
    r = factor_credential_age(None)
    assert r.raw_value == 1.0 and "never been rotated" in r.remediation


def test_credential_age_scales_linearly_and_clamps():
    half = factor_credential_age(NOW - timedelta(days=45), max_age_days=90)
    assert half.raw_value == pytest.approx(0.5, abs=0.02)
    old = factor_credential_age(NOW - timedelta(days=400), max_age_days=90)
    assert old.raw_value == 1.0 and "rotate now" in old.remediation


def test_naive_datetimes_are_treated_as_utc():
    naive = (NOW - timedelta(days=45)).replace(tzinfo=None)
    assert factor_credential_age(naive, 90).raw_value == pytest.approx(0.5, abs=0.02)


# --------------------------------------------------------------- staleness

def test_never_used_is_max_staleness():
    r = factor_staleness(None)
    assert r.raw_value == 1.0 and "never been used" in r.remediation


def test_recently_used_is_low_staleness():
    r = factor_staleness(NOW - timedelta(days=1), stale_threshold_days=30)
    assert r.raw_value < 0.1 and r.remediation is None


# --------------------------------------------------------- exposure surface

def test_exposure_surface_clamps_and_flags_over_limit():
    assert factor_exposure_surface(5, max_expected=10).raw_value == pytest.approx(0.5)
    wide = factor_exposure_surface(25, max_expected=10)
    assert wide.raw_value == 1.0 and "25 services" in wide.remediation


def test_exposure_surface_handles_zero_max_expected():
    assert factor_exposure_surface(3, max_expected=0).raw_value == 1.0


# ------------------------------------------------------------- blast radius

@pytest.mark.parametrize(
    "level,scope,expected",
    [
        ("readonly", "single", 0.05),
        ("standard", "single", 0.25),
        ("admin", "multi", 0.675),
        ("superadmin", "organization", 1.0),
    ],
)
def test_blast_radius_is_privilege_times_scope(level, scope, expected):
    assert factor_blast_radius(level, scope).raw_value == pytest.approx(expected)


def test_blast_radius_unknown_values_fall_back_to_defaults():
    r = factor_blast_radius("mystery", "galaxy")
    assert r.raw_value == pytest.approx(0.25)  # standard (0.5) * single (0.5)


def test_blast_radius_is_case_insensitive():
    assert factor_blast_radius("ADMIN", "organization").raw_value == pytest.approx(0.9)


# ---------------------------------------------------------------- scorer

def test_best_case_identity_scores_low():
    identity = make_identity(last_rotated_at=NOW, last_used_at=NOW)
    score = compute_risk_score(
        identity, granted_count=4, used_count=4, reachable_services=1,
        privilege_level="readonly",
    )
    assert score.severity == "LOW"
    assert score.score < 10


def test_worst_case_identity_is_critical_and_clamped():
    identity = make_identity()  # never rotated, never used
    score = compute_risk_score(
        identity, granted_count=50, used_count=0, reachable_services=40,
        privilege_level="superadmin", account_scope="organization",
    )
    assert score.score == 100.0
    assert score.severity == "CRITICAL"


def test_score_equals_sum_of_factor_contributions():
    identity = make_identity(last_rotated_at=NOW - timedelta(days=30))
    score = compute_risk_score(identity, granted_count=10, used_count=3, reachable_services=4)
    assert len(score.factors) == 5
    assert score.score == pytest.approx(sum(f.contribution for f in score.factors), abs=0.01)


def test_scoring_is_deterministic():
    identity = make_identity(last_rotated_at=NOW - timedelta(days=10), last_used_at=NOW)
    kwargs = dict(granted_count=8, used_count=2, reachable_services=3, privilege_level="elevated")
    assert compute_risk_score(identity, **kwargs).score == compute_risk_score(identity, **kwargs).score


@pytest.mark.parametrize(
    "value,band",
    [(0, "LOW"), (24.99, "LOW"), (25, "MEDIUM"), (49.99, "MEDIUM"),
     (50, "HIGH"), (74.99, "HIGH"), (75, "CRITICAL"), (100, "CRITICAL")],
)
def test_severity_band_boundaries(value, band):
    assert RiskScore.severity_from_score(value) == band


def test_batch_score_applies_per_identity_context():
    risky = make_identity(external_id="risky")
    safe = make_identity(external_id="safe", last_rotated_at=NOW, last_used_at=NOW)
    context = {
        "risky": dict(granted_count=20, used_count=0, privilege_level="admin"),
        "safe": dict(granted_count=3, used_count=3, privilege_level="readonly"),
    }
    scored = batch_score([risky, safe], context)
    assert [i.external_id for i in scored] == ["risky", "safe"]
    assert all(i.risk_score is not None for i in scored)
    assert scored[0].risk_score.score > scored[1].risk_score.score


def test_batch_score_missing_context_uses_defaults():
    (scored,) = batch_score([make_identity(external_id="unknown")], {})
    assert scored.risk_score is not None
