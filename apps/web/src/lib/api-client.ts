/**
 * Typed API client for the AgentGuard control plane.
 * All methods require an auth token (obtained from Clerk's useAuth hook).
 */

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000"

export type NHIType = "API_KEY" | "SERVICE_ACCOUNT" | "OAUTH_TOKEN" | "BOT" | "AGENT_CREDENTIAL"
export type Provider = "AWS" | "AZURE" | "GCP" | "GITHUB" | "GITLAB"
export type Classification = "AI_AGENT" | "CICD" | "INTEGRATION" | "HUMAN_PROXY" | "UNKNOWN"
export type NHIStatus = "ACTIVE" | "STALE" | "ORPHANED" | "REVOKED"
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
export type ComplianceFramework = "SOC2" | "NIST_800_53" | "PCI_DSS" | "ISO_27001"
export type ControlStatus = "PASS" | "FAIL" | "WARNING" | "NOT_APPLICABLE"
export type WebhookType = "SLACK" | "PAGERDUTY" | "GENERIC" | "SPLUNK" | "DATADOG"
export type AlertStatus = "OPEN" | "ACKNOWLEDGED" | "RESOLVED"

export interface RiskFactor {
  name: string
  weight: number
  raw_value: number
  contribution: number
  remediation: string | null
}

export interface RiskScore {
  score: number
  severity: Severity
  computed_at: string
  factors: RiskFactor[]
}

export interface NHIIdentity {
  id: string
  external_id: string
  name: string
  type: NHIType
  provider: Provider
  classification: Classification
  owner_email: string | null
  status: NHIStatus
  created_at: string | null
  last_used_at: string | null
  last_rotated_at: string | null
  last_scanned_at: string
  risk_score: RiskScore | null
  raw_metadata: Record<string, unknown>
}

export interface NHIListResponse {
  items: NHIIdentity[]
  total: number
  page: number
  page_size: number
}

export interface PolicyRule {
  id: string
  name: string
  description: string | null
  yaml_definition: string
  enforcement_mode: string
  enabled: boolean
  compliance_mappings: string[]
  created_by: string | null
  created_at: string
}

export interface RiskStats {
  total: number; critical: number; high: number; medium: number; low: number
  unscored: number; avg_score: number
}
export interface TopRiskyIdentity {
  id: string; name: string; provider: string; type: string
  score: number; severity: string; top_factor: string | null; top_remediation: string | null
}
export interface ControlResult {
  control_id: string; control_name: string; description: string
  status: ControlStatus; evidence: string; affected_count: number; remediation: string | null
}
export interface ComplianceReport {
  framework: ComplianceFramework; generated_at: string
  overall_score: number; controls_total: number; controls_passing: number
  controls_failing: number; controls_warning: number; controls: ControlResult[]
}
export interface Webhook {
  id: string; name: string; url: string; type: WebhookType
  enabled: boolean; events: string[]; created_at: string
  last_triggered_at: string | null; last_error: string | null
}
export interface AlertItem {
  id: string; type: string; severity: string; title: string
  description: string | null; resource_type: string | null
  resource_id: string | null; status: string; created_at: string
}
export interface ViolationItem {
  id: string; nhi_id: string; policy_id: string; policy_name: string
  detected_at: string; resolved_at: string | null; resolution: string | null
}

export interface JITGrant {
  id: string
  nhi_id: string
  scope: Record<string, unknown>
  reason: string
  approved_by: string | null
  issued_at: string
  expires_at: string
  status: string
  credential_hint: string | null
}

async function request<T>(
  path: string,
  token: string,
  options: RequestInit = {}
): Promise<T> {
  const res = await fetch(`${BASE_URL}/v1${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(options.headers ?? {}),
    },
  })
  if (!res.ok) {
    const error = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(error.detail ?? `API error ${res.status}`)
  }
  return res.json() as Promise<T>
}

export const apiClient = {
  identities: {
    list: (token: string, params?: Record<string, string>) => {
      const qs = params ? "?" + new URLSearchParams(params).toString() : ""
      return request<NHIListResponse>(`/identities${qs}`, token)
    },
    get: (token: string, id: string) =>
      request<NHIIdentity>(`/identities/${id}`, token),
    rotate: (token: string, id: string) =>
      request<{ message: string }>(`/identities/${id}/rotate`, token, { method: "POST", body: JSON.stringify({ reason: "Manual" }) }),
    revoke: (token: string, id: string, reason: string) =>
      request<{ message: string }>(`/identities/${id}/revoke`, token, { method: "POST", body: JSON.stringify({ reason }) }),
    triggerScan: (token: string) =>
      request<{ message: string }>(`/identities/scans`, token, { method: "POST", body: JSON.stringify({}) }),
  },
  risk: {
    stats: (token: string) => request<RiskStats>("/risk/stats", token),
    top: (token: string, limit = 20) => request<TopRiskyIdentity[]>(`/risk/top?limit=${limit}`, token),
    history: (token: string, id: string) => request<unknown[]>(`/risk/${id}/history`, token),
    recompute: (token: string) => request<{ count: number }>("/risk/recompute", token, { method: "POST" }),
  },
  compliance: {
    report: (token: string, framework: ComplianceFramework) =>
      request<ComplianceReport>(`/compliance/report?framework=${framework}`, token),
  },
  integrations: {
    webhooks: {
      list: (token: string) => request<Webhook[]>("/integrations/webhooks", token),
      create: (token: string, body: { name: string; url: string; type: WebhookType; events: string[] }) =>
        request<Webhook>("/integrations/webhooks", token, { method: "POST", body: JSON.stringify(body) }),
      delete: (token: string, id: string) =>
        request<void>(`/integrations/webhooks/${id}`, token, { method: "DELETE" }),
      test: (token: string, id: string) =>
        request<{ success: boolean; error?: string }>(`/integrations/webhooks/${id}/test`, token, { method: "POST" }),
    },
    alerts: {
      list: (token: string, status?: string) =>
        request<AlertItem[]>(`/integrations/alerts${status ? `?status=${status}` : ""}`, token),
      acknowledge: (token: string, id: string) =>
        request<void>(`/integrations/alerts/${id}/acknowledge`, token, { method: "POST" }),
    },
  },
  policies: {
    list: (token: string) => request<PolicyRule[]>("/policies", token),
    create: (token: string, body: { name: string; yaml_definition: string; enforcement_mode?: string; compliance_mappings?: string[] }) =>
      request<PolicyRule>("/policies", token, { method: "POST", body: JSON.stringify(body) }),
    violations: (token: string) => request<ViolationItem[]>("/policies/violations", token),
  },
  jit: {
    list: (token: string) => request<JITGrant[]>("/jit/grants", token),
    create: (token: string, body: { nhi_id: string; scope: object; reason: string; ttl_minutes?: number }) =>
      request<JITGrant>("/jit/grants", token, { method: "POST", body: JSON.stringify(body) }),
    revoke: (token: string, id: string) =>
      request<void>(`/jit/grants/${id}`, token, { method: "DELETE" }),
  },
}
