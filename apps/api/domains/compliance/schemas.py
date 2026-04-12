from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel


class ComplianceFramework(str, Enum):
    SOC2 = "SOC2"
    NIST_800_53 = "NIST_800_53"
    PCI_DSS = "PCI_DSS"
    ISO_27001 = "ISO_27001"


class ControlStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ControlResult(BaseModel):
    control_id: str
    control_name: str
    description: str
    status: ControlStatus
    evidence: str  # human-readable explanation of why it passed/failed
    affected_count: int  # number of NHIs contributing to this result
    remediation: str | None


class ComplianceReportResponse(BaseModel):
    framework: ComplianceFramework
    generated_at: datetime
    overall_score: float  # 0-100, % of controls passing
    controls_total: int
    controls_passing: int
    controls_failing: int
    controls_warning: int
    controls: list[ControlResult]
