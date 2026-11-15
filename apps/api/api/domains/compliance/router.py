from __future__ import annotations

from fastapi import APIRouter

from api.core.auth import Auth

from .schemas import ComplianceFramework, ComplianceReportResponse
from .service import generate_report

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/report", response_model=ComplianceReportResponse)
async def compliance_report(
    framework: ComplianceFramework = ComplianceFramework.SOC2,
    auth: Auth = None,
):
    return await generate_report(auth.tenant_id, framework)
