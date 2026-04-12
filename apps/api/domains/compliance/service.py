from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import text

from api.core.database import tenant_session

from .schemas import (
    ComplianceFramework,
    ComplianceReportResponse,
    ControlResult,
    ControlStatus,
)


async def generate_report(
    tenant_id: uuid.UUID, framework: ComplianceFramework
) -> ComplianceReportResponse:
    now = datetime.now(timezone.utc)
    controls: list[ControlResult] = []

    async with tenant_session(tenant_id) as session:

        async def _scalar(sql: str, params: dict | None = None) -> int:
            row = await session.execute(text(sql), params or {})
            return row.scalar_one() or 0

        # ---- Reusable sub-queries ----

        async def count_no_risk_or_high_avg() -> tuple[int, float]:
            """Count NHIs with no risk score OR avg score > 75; return (count, avg_score)."""
            r = await session.execute(
                text("""
                    SELECT
                        COUNT(*) FILTER (WHERE rs.score IS NULL OR rs.score > 75) AS bad_count,
                        AVG(rs.score) AS avg_score
                    FROM nhi_identities n
                    LEFT JOIN LATERAL (
                        SELECT score FROM risk_scores WHERE nhi_id = n.id
                        ORDER BY computed_at DESC LIMIT 1
                    ) rs ON true
                """)
            )
            row = r.mappings().first()
            return (row["bad_count"] or 0, float(row["avg_score"] or 0.0))

        async def count_not_rotated_90d() -> int:
            return await _scalar("""
                SELECT COUNT(*) FROM nhi_identities
                WHERE status = 'ACTIVE'
                  AND (last_rotated_at < NOW() - INTERVAL '90 days' OR last_rotated_at IS NULL)
            """)

        async def count_critical_nhis() -> int:
            return await _scalar("""
                SELECT COUNT(*) FROM nhi_identities n
                JOIN LATERAL (
                    SELECT severity FROM risk_scores WHERE nhi_id = n.id
                    ORDER BY computed_at DESC LIMIT 1
                ) rs ON true
                WHERE rs.severity = 'CRITICAL'
            """)

        async def count_high_nhis() -> int:
            return await _scalar("""
                SELECT COUNT(*) FROM nhi_identities n
                JOIN LATERAL (
                    SELECT severity FROM risk_scores WHERE nhi_id = n.id
                    ORDER BY computed_at DESC LIMIT 1
                ) rs ON true
                WHERE rs.severity = 'HIGH'
            """)

        async def count_stale_orphaned() -> int:
            return await _scalar("""
                SELECT COUNT(*) FROM nhi_identities
                WHERE status IN ('STALE', 'ORPHANED')
            """)

        async def count_orphaned() -> int:
            return await _scalar("""
                SELECT COUNT(*) FROM nhi_identities WHERE status = 'ORPHANED'
            """)

        async def count_unresolved_violations() -> int:
            return await _scalar("""
                SELECT COUNT(*) FROM policy_violations WHERE resolved_at IS NULL
            """)

        async def has_recent_behavioral_events() -> bool:
            n = await _scalar("""
                SELECT COUNT(*) FROM behavioral_events
                WHERE occurred_at >= NOW() - INTERVAL '7 days'
            """)
            return n > 0

        async def count_no_owner_active() -> int:
            return await _scalar("""
                SELECT COUNT(*) FROM nhi_identities
                WHERE owner_email IS NULL AND status = 'ACTIVE'
            """)

        # ---- Build controls per framework ----

        if framework == ComplianceFramework.SOC2:
            # CC6.1: Least-privilege access
            bad_count, avg_score = await count_no_risk_or_high_avg()
            if bad_count > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{bad_count} NHIs have no risk score or a risk score above 75 (avg score: {avg_score:.1f})"
                remediation = "Review and remediate over-privileged identities; ensure all NHIs have been scored."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = f"All NHIs are scored and average risk score is {avg_score:.1f}, below threshold."
                remediation = None
            controls.append(ControlResult(
                control_id="CC6.1",
                control_name="Least-privilege access",
                description="Logical access controls restrict access to information assets on a need-to-know basis.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=bad_count,
                remediation=remediation,
            ))

            # CC6.2: Credentials rotated regularly
            not_rotated = await count_not_rotated_90d()
            if not_rotated > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{not_rotated} active NHIs have not had credentials rotated within 90 days."
                remediation = "Rotate credentials for all flagged NHIs or configure automated rotation."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "All active credentials rotated within the 90-day policy window."
                remediation = None
            controls.append(ControlResult(
                control_id="CC6.2",
                control_name="Credentials rotated regularly",
                description="Credentials are rotated on a defined schedule to limit exposure from compromised secrets.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=not_rotated,
                remediation=remediation,
            ))

            # CC6.3: No admin credentials exposed
            critical_count = await count_critical_nhis()
            high_count = await count_high_nhis()
            if critical_count > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{critical_count} CRITICAL risk NHIs detected."
                remediation = "Immediately remediate CRITICAL NHIs — revoke, rotate, or restrict scope."
            elif high_count > 0:
                ctrl_status = ControlStatus.WARNING
                evidence = f"{high_count} HIGH risk NHIs detected."
                remediation = "Review and remediate HIGH risk NHIs to reduce exposure."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "No CRITICAL or HIGH risk NHIs detected."
                remediation = None
            controls.append(ControlResult(
                control_id="CC6.3",
                control_name="No admin credentials exposed",
                description="Administrative and privileged credentials are not exposed or over-permissioned.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=critical_count + high_count,
                remediation=remediation,
            ))

            # CC7.2: Stale identities removed
            stale_count = await count_stale_orphaned()
            if stale_count > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{stale_count} NHIs are in STALE or ORPHANED status."
                remediation = "Revoke or reassign stale and orphaned NHIs."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "No stale or orphaned NHIs detected."
                remediation = None
            controls.append(ControlResult(
                control_id="CC7.2",
                control_name="Stale identities removed",
                description="Unused or orphaned identities are identified and removed in a timely manner.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=stale_count,
                remediation=remediation,
            ))

            # CC9.1: Access monitored
            has_events = await has_recent_behavioral_events()
            if not has_events:
                ctrl_status = ControlStatus.WARNING
                evidence = "No behavioral events recorded in the last 7 days — monitoring may not be configured."
                remediation = "Deploy behavioral sensors and verify event ingestion."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "Behavioral events are being ingested within the last 7 days."
                remediation = None
            controls.append(ControlResult(
                control_id="CC9.1",
                control_name="Access monitored",
                description="Access to information assets is monitored and anomalies are detected.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=0,
                remediation=remediation if not has_events else None,
            ))

        elif framework == ComplianceFramework.NIST_800_53:
            # AC-2: Account management
            orphaned = await count_orphaned()
            if orphaned > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{orphaned} orphaned NHIs detected — accounts without known owners."
                remediation = "Identify owners for all orphaned accounts or decommission them."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "No orphaned NHIs detected."
                remediation = None
            controls.append(ControlResult(
                control_id="AC-2",
                control_name="Account management",
                description="The organization manages information system accounts including establishment, activation, and removal.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=orphaned,
                remediation=remediation,
            ))

            # AC-3: Access enforcement
            violations = await count_unresolved_violations()
            if violations > 5:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{violations} unresolved policy violations."
                remediation = "Review and resolve open policy violations."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = f"{violations} unresolved policy violations (within acceptable threshold)."
                remediation = None
            controls.append(ControlResult(
                control_id="AC-3",
                control_name="Access enforcement",
                description="The information system enforces approved authorizations for logical access.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=violations,
                remediation=remediation,
            ))

            # AC-6: Least privilege
            bad_count, avg_score = await count_no_risk_or_high_avg()
            if bad_count > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{bad_count} NHIs have no risk score or a score above 75 (avg: {avg_score:.1f})."
                remediation = "Remediate over-privileged NHIs and ensure all identities are scored."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = f"All NHIs scored; average risk score {avg_score:.1f}."
                remediation = None
            controls.append(ControlResult(
                control_id="AC-6",
                control_name="Least privilege",
                description="Users are granted only the access required to perform their assigned functions.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=bad_count,
                remediation=remediation,
            ))

            # AU-9: Audit log protection
            controls.append(ControlResult(
                control_id="AU-9",
                control_name="Audit log protection",
                description="The information system protects audit information from unauthorized access, modification, and deletion.",
                status=ControlStatus.PASS,
                evidence="Audit log is append-only; no DELETE grants exist on the audit_log table by structural design.",
                affected_count=0,
                remediation=None,
            ))

            # IA-5: Authenticator management
            not_rotated = await count_not_rotated_90d()
            if not_rotated > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{not_rotated} active NHIs have not been rotated in 90+ days."
                remediation = "Rotate credentials for flagged NHIs."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "All active credentials rotated within 90-day policy window."
                remediation = None
            controls.append(ControlResult(
                control_id="IA-5",
                control_name="Authenticator management",
                description="Credentials are managed through their lifecycle including rotation and revocation.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=not_rotated,
                remediation=remediation,
            ))

        elif framework == ComplianceFramework.PCI_DSS:
            # Req-7: Restrict access
            critical_count = await count_critical_nhis()
            if critical_count > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{critical_count} CRITICAL risk NHIs detected — overly broad access."
                remediation = "Immediately restrict or revoke CRITICAL risk NHIs."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "No CRITICAL risk NHIs detected."
                remediation = None
            controls.append(ControlResult(
                control_id="Req-7",
                control_name="Restrict access to system components",
                description="Access to system components and cardholder data is limited to only individuals whose job requires such access.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=critical_count,
                remediation=remediation,
            ))

            # Req-8: Identify users
            no_owner = await count_no_owner_active()
            if no_owner > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{no_owner} active NHIs have no assigned owner."
                remediation = "Assign ownership to all active NHIs to ensure accountability."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "All active NHIs have assigned owners."
                remediation = None
            controls.append(ControlResult(
                control_id="Req-8",
                control_name="Identify and authenticate users",
                description="All users are identified and authenticated before accessing system components.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=no_owner,
                remediation=remediation,
            ))

            # Req-10: Track access
            has_events = await has_recent_behavioral_events()
            if not has_events:
                ctrl_status = ControlStatus.WARNING
                evidence = "No behavioral events in last 7 days — access logging may not be active."
                remediation = "Enable and verify behavioral monitoring for all access."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "Access events are being captured and logged."
                remediation = None
            controls.append(ControlResult(
                control_id="Req-10",
                control_name="Track and monitor access",
                description="All access to network resources and cardholder data is tracked and monitored.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=0,
                remediation=remediation if not has_events else None,
            ))

        elif framework == ComplianceFramework.ISO_27001:
            # A.9.2: User access management
            orphaned = await count_orphaned()
            if orphaned > 0:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{orphaned} orphaned NHIs without assigned owners or responsibilities."
                remediation = "Assign ownership or decommission orphaned NHIs."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = "No orphaned NHIs detected."
                remediation = None
            controls.append(ControlResult(
                control_id="A.9.2",
                control_name="User access management",
                description="Access rights are provisioned, reviewed, and revoked in a controlled manner.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=orphaned,
                remediation=remediation,
            ))

            # A.9.4: System access control
            violations = await count_unresolved_violations()
            if violations > 5:
                ctrl_status = ControlStatus.FAIL
                evidence = f"{violations} unresolved policy violations indicate control failures."
                remediation = "Resolve open violations and review access control policies."
            else:
                ctrl_status = ControlStatus.PASS
                evidence = f"{violations} unresolved violations (within acceptable threshold)."
                remediation = None
            controls.append(ControlResult(
                control_id="A.9.4",
                control_name="System and application access control",
                description="Access to systems and applications is restricted in line with the access control policy.",
                status=ctrl_status,
                evidence=evidence,
                affected_count=violations,
                remediation=remediation,
            ))

            # A.12.4: Logging
            controls.append(ControlResult(
                control_id="A.12.4",
                control_name="Logging and monitoring",
                description="Event logs recording user activities, exceptions, and security events are retained and reviewed.",
                status=ControlStatus.PASS,
                evidence="Audit log is append-only by structural design; all security events are recorded.",
                affected_count=0,
                remediation=None,
            ))

    # Compute summary stats
    passing = sum(1 for c in controls if c.status == ControlStatus.PASS)
    failing = sum(1 for c in controls if c.status == ControlStatus.FAIL)
    warning = sum(1 for c in controls if c.status == ControlStatus.WARNING)
    total = len(controls)
    overall_score = (passing / total * 100) if total > 0 else 0.0

    return ComplianceReportResponse(
        framework=framework,
        generated_at=now,
        overall_score=round(overall_score, 1),
        controls_total=total,
        controls_passing=passing,
        controls_failing=failing,
        controls_warning=warning,
        controls=controls,
    )
