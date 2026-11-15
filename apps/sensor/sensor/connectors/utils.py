"""
Shared utilities for all cloud connector scanners.
Import from here — never redefine these across scanner modules.
"""
from __future__ import annotations

from datetime import datetime, timezone


def to_utc(dt: datetime | None) -> datetime | None:
    """Normalize a naive or tz-aware datetime to UTC. Returns None if input is None."""
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def classify_by_name(name: str) -> str:
    """
    Heuristic classification of an NHI based on its display name.
    Returns one of: AI_AGENT, CICD, INTEGRATION, UNKNOWN.
    """
    name_lower = name.lower()
    if any(p in name_lower for p in ["agent", "copilot", "llm", "gpt", "ai-", "-ai", "claude", "openai", "anthropic"]):
        return "AI_AGENT"
    if any(p in name_lower for p in ["github", "gitlab", "jenkins", "circleci", "codebuild", "deploy", "ci-", "-ci", "pipeline", "devops"]):
        return "CICD"
    if any(p in name_lower for p in ["datadog", "splunk", "pagerduty", "jira", "slack", "terraform", "pulumi", "monitor", "sentinel", "integration"]):
        return "INTEGRATION"
    return "UNKNOWN"


def infer_privilege_from_policies(policy_names: list[str]) -> str:
    """
    Infer a privilege level string from a list of IAM policy names.
    Used by multiple cloud scanners for blast-radius scoring.
    """
    text = " ".join(policy_names).lower()
    if "administratoraccess" in text or "fullaccess" in text:
        return "admin"
    if "poweruser" in text or "readwrite" in text:
        return "elevated"
    if "readonly" in text or "readonlyaccess" in text:
        return "readonly"
    return "standard"
