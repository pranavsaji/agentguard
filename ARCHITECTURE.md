# AgentGuard — Chief Architect Plan
## Non-Human Identity Governance for the Agentic AI Era

---

## Context

Enterprise AI deployment is creating unmanaged non-human identity (NHI) sprawl at a pace existing IAM tools (Okta, CyberArk, SailPoint) cannot address — they were built for human users. AgentGuard is a purpose-built governance platform for NHIs: API keys, service accounts, OAuth tokens, bot credentials, and AI agent identities. The product must be multi-tenant SaaS with a hybrid deployment option (scanner runs inside the customer's account, control plane stays in AgentGuard cloud). All four major cloud providers (AWS, Azure, GCP, GitHub/GitLab) must be supported at MVP.

---

## 1. Architectural Philosophy

**Modular monolith, extract on proven need.** Microservices are premature for a Series A security startup — they multiply ops burden and split hiring requirements without delivering scale benefits until you exceed what a single well-written service can handle. The platform is structured as a single FastAPI application with clean internal domain boundaries. When a single domain (e.g., the behavioral ML engine) has independent scaling or language needs, it gets extracted then — not before.

**Two-plane architecture.** The hybrid deployment requirement forces a clean separation between:
- **Control Plane** (AgentGuard-hosted): API, dashboard, policy engine, reporting, tenant management
- **Data Plane** (customer VPC or AgentGuard VPC): Scanners, credential rotation agents, behavioral telemetry collectors

This separation also becomes a *security selling point* — customers can prove IAM data never leaves their boundary.

**Schema-per-tenant isolation.** For a security product, sharing rows between tenants is unacceptable. Separate databases are too expensive at scale. PostgreSQL schema-per-tenant with Row-Level Security (RLS) gives full data isolation with shared infrastructure economics.

---

## 2. System Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                        CLIENT LAYER                              │
│           Web Dashboard  │  REST API  │  CLI  │  Webhooks        │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTPS + JWT (Clerk OIDC)
┌────────────────────────────▼─────────────────────────────────────┐
│                   CONTROL PLANE (AgentGuard SaaS)                │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              FastAPI Application Server                  │    │
│  │                                                          │    │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │    │
│  │  │ Inventory  │  │  Risk      │  │   Policy Engine    │ │    │
│  │  │ Service    │  │  Engine    │  │   (OPA / custom)   │ │    │
│  │  └────────────┘  └────────────┘  └────────────────────┘ │    │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────────────┐ │    │
│  │  │ JIT Access │  │ Compliance │  │  Integration Hub   │ │    │
│  │  │ Service    │  │ Reporter   │  │  (Vault/Okta/SIEM) │ │    │
│  │  └────────────┘  └────────────┘  └────────────────────┘ │    │
│  │  ┌────────────┐  ┌────────────┐                          │    │
│  │  │ Behavioral │  │ Notify     │                          │    │
│  │  │ Engine     │  │ Service    │                          │    │
│  │  └────────────┘  └────────────┘                          │    │
│  └──────────────────────┬──────────────────────────────────┘    │
│                         │                                        │
│  ┌──────────────────────▼──────────────────────────────────┐    │
│  │                    DATA LAYER                            │    │
│  │  PostgreSQL    ClickHouse    Redis       Kafka/SQS       │    │
│  │  (Inventory +  (Behavioral  (Session +  (Event           │    │
│  │   Tenants,      time-series) JIT tokens  streaming)      │    │
│  │   schema/tenant)            rate limits)                 │    │
│  └─────────────────────────────────────────────────────────┘    │
└──────────────────────────┬───────────────────────────────────────┘
                           │ Encrypted gRPC (mTLS)
┌──────────────────────────▼───────────────────────────────────────┐
│              DATA PLANE (Customer VPC or AgentGuard VPC)         │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 AgentGuard Sensor Pod (K8s)              │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │   │
│  │  │  AWS     │ │  Azure   │ │   GCP    │ │  GitHub/  │  │   │
│  │  │ Scanner  │ │ Scanner  │ │ Scanner  │ │  GitLab   │  │   │
│  │  └──────────┘ └──────────┘ └──────────┘ └───────────┘  │   │
│  │  ┌──────────────────────┐  ┌───────────────────────────┐│   │
│  │  │  Rotation Agent      │  │  Telemetry Collector      ││   │
│  │  │  (executes rotations │  │  (streams behavioral data ││   │
│  │  │   approved upstream) │  │   to control plane)       ││   │
│  │  └──────────────────────┘  └───────────────────────────┘│   │
│  └──────────────────────────────────────────────────────────┘   │
│                        Cloud APIs (read-only + rotation scope)   │
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Repository Structure (Monorepo)

```
agentguard/
├── apps/
│   ├── web/                        # Next.js 15 App Router dashboard
│   │   ├── app/
│   │   │   ├── (auth)/             # Clerk auth pages
│   │   │   ├── dashboard/          # Main app routes
│   │   │   │   ├── inventory/      # NHI catalog views
│   │   │   │   ├── risk/           # Risk scoring dashboard
│   │   │   │   ├── policies/       # Policy management
│   │   │   │   ├── jit/            # JIT access requests
│   │   │   │   ├── compliance/     # Reports
│   │   │   │   └── integrations/   # Connector config
│   │   │   └── api/                # Next.js API routes (thin BFF layer)
│   │   ├── components/
│   │   │   ├── ui/                 # shadcn/ui primitives
│   │   │   ├── inventory/          # NHI table, detail panels
│   │   │   ├── risk/               # Risk score cards, heatmaps
│   │   │   └── charts/             # Behavioral timeline charts
│   │   └── lib/
│   │       ├── api-client.ts       # Typed API client (generated from OpenAPI)
│   │       └── auth.ts             # Clerk config
│   │
│   ├── api/                        # FastAPI control plane
│   │   ├── main.py                 # App entrypoint, router registration
│   │   ├── core/
│   │   │   ├── config.py           # Settings (pydantic-settings)
│   │   │   ├── database.py         # SQLAlchemy engine + tenant context
│   │   │   ├── auth.py             # JWT validation, tenant extraction
│   │   │   └── events.py           # Kafka/SQS producer
│   │   ├── domains/
│   │   │   ├── inventory/          # NHI catalog domain
│   │   │   │   ├── models.py       # SQLAlchemy ORM models
│   │   │   │   ├── schemas.py      # Pydantic request/response schemas
│   │   │   │   ├── service.py      # Business logic
│   │   │   │   └── router.py       # FastAPI routes
│   │   │   ├── risk/               # Risk engine domain
│   │   │   ├── policy/             # Policy engine domain
│   │   │   ├── jit/                # JIT access domain
│   │   │   ├── behavioral/         # Anomaly detection domain
│   │   │   ├── compliance/         # Reporting domain
│   │   │   ├── integrations/       # Integration hub domain
│   │   │   └── tenants/            # Tenant management domain
│   │   └── workers/
│   │       ├── scan_scheduler.py   # Triggers scans via events
│   │       ├── risk_recalc.py      # Async risk score updates
│   │       └── rotation_orchestrator.py
│   │
│   └── sensor/                     # Data plane sensor (deployed in customer VPC)
│       ├── main.py                 # Sensor entrypoint
│       ├── connectors/
│       │   ├── base.py             # Abstract connector interface
│       │   ├── aws/
│       │   │   ├── iam_scanner.py  # IAM users, roles, access keys
│       │   │   ├── secrets_scanner.py
│       │   │   └── cloudtrail.py   # Activity log collector
│       │   ├── azure/
│       │   │   ├── entra_scanner.py  # Service principals, app registrations
│       │   │   └── keyvault_scanner.py
│       │   ├── gcp/
│       │   │   ├── iam_scanner.py
│       │   │   └── secret_manager.py
│       │   └── github/
│       │       ├── secrets_scanner.py  # Actions secrets, tokens
│       │       └── app_scanner.py
│       ├── rotation/
│       │   ├── aws_rotator.py
│       │   ├── azure_rotator.py
│       │   └── gcp_rotator.py
│       └── telemetry/
│           └── emitter.py          # Streams behavioral events to control plane
│
├── packages/
│   ├── nhi-schema/                 # Shared NHI canonical data model (JSON Schema + Python types)
│   │   └── models.py               # NHIIdentity, RiskScore, PolicyRule, etc.
│   └── risk-engine/                # Shared risk scoring logic (used by API + sensor)
│       ├── scorer.py               # Scoring algorithm
│       └── factors.py              # Risk factor weights
│
├── infrastructure/
│   ├── terraform/
│   │   ├── modules/
│   │   │   ├── control-plane/      # EKS cluster, RDS, ClickHouse, Redis, MSK
│   │   │   └── sensor/             # Helm chart + IAM roles for customer deployment
│   │   └── environments/
│   │       ├── prod/
│   │       └── staging/
│   └── helm/
│       └── agentguard-sensor/      # Helm chart for customer-side sensor deployment
│
├── workflows/                      # WAT framework workflow SOPs
│   ├── onboard_tenant.md
│   ├── scan_cloud_env.md
│   ├── rotate_credential.md
│   └── investigate_anomaly.md
│
└── tools/                          # WAT framework execution scripts
    ├── provision_tenant.py
    ├── trigger_scan.py
    └── generate_compliance_report.py
```

---

## 4. Domain Service Specifications

### 4.1 NHI Inventory Service
The single source of truth for all non-human identities.

**Canonical NHI Schema:**
```python
class NHIIdentity:
    id: UUID
    tenant_id: UUID
    external_id: str              # Cloud-native ID (ARN, Object ID, etc.)
    name: str
    type: NHIType                 # API_KEY | SERVICE_ACCOUNT | OAUTH_TOKEN | BOT | AGENT_CREDENTIAL
    provider: Provider            # AWS | AZURE | GCP | GITHUB | GITLAB
    classification: Classification # AI_AGENT | CICD | INTEGRATION | HUMAN_PROXY | UNKNOWN
    owner_id: str | None          # Mapped human owner (if known)
    created_at: datetime
    last_used_at: datetime | None
    last_rotated_at: datetime | None
    permissions: list[Permission] # Actual granted permissions
    risk_score: RiskScore
    status: Status                # ACTIVE | STALE | ORPHANED | REVOKED
    metadata: dict                # Provider-specific raw data
```

**Key APIs:**
- `GET /v1/identities` — paginated, filterable inventory
- `GET /v1/identities/{id}` — full detail with permission tree
- `POST /v1/identities/{id}/rotate` — trigger rotation
- `POST /v1/identities/{id}/revoke` — immediate revocation
- `GET /v1/identities/{id}/activity` — behavioral timeline

### 4.2 Risk Engine

Risk scores are computed on a 0–100 scale. The scoring is deterministic, auditable, and explainable (no black boxes — CISOs need to justify to auditors).

**Risk Factor Weights (v1):**

| Factor | Weight | Signal |
|--------|--------|--------|
| Over-permission ratio | 30% | (granted permissions) / (used permissions) in last 90 days |
| Credential age | 20% | Days since last rotation vs. policy max |
| Staleness | 20% | Days since last use (0 = never used = max risk) |
| Exposure surface | 15% | Number of services/APIs the credential can reach |
| Blast radius | 15% | Privilege level × account scope |

Score is recomputed async on: scan completion, usage event received, policy change, manual trigger.

**Explainability:** Every score includes a `factors` array showing each factor's contribution and the remediation action.

### 4.3 Policy Engine

**Architecture:** Open Policy Agent (OPA) as the evaluation core, with AgentGuard providing a management layer (CRUD for policies, tenant isolation, violation tracking).

Policies are written in AgentGuard's own DSL (YAML-based), compiled to Rego internally. This shields users from Rego complexity while retaining OPA's expressiveness.

**Sample Policy DSL:**
```yaml
name: no-stale-api-keys
description: API keys unused for 30+ days must be flagged for rotation
applies_to:
  types: [API_KEY]
  providers: [AWS, GCP, AZURE]
condition:
  days_since_last_use: { gte: 30 }
action: FLAG         # FLAG | ALERT | AUTO_ROTATE | REVOKE
severity: HIGH
compliance_mappings:
  - SOC2_CC6.1
  - NIST_AC-2
```

**Enforcement modes:**
- `MONITOR` — log violations, no action
- `ALERT` — notify stakeholders
- `ENFORCE` — block JIT grant, trigger rotation
- `AUTO_REMEDIATE` — execute rotation/revocation automatically

### 4.4 Behavioral Engine (V2, foundation in MVP)

**Goal:** Detect when an AI agent deviates from its learned behavioral baseline — the primary signal for credential compromise or agent misconfiguration.

**Architecture:**
- Telemetry events stream from the sensor via gRPC to the control plane
- Events stored in ClickHouse (tenant-partitioned) with 90-day hot storage, 1-year cold
- Baseline built per NHI over first 14 days (supervised grace period)
- Anomaly detection: **Isolation Forest** for multivariate outlier detection on API call vectors

**Behavioral Features per NHI:**
```
- api_call_rate_per_hour (rolling 24h)
- unique_endpoints_accessed (rolling 24h)
- data_egress_bytes (rolling 24h)
- time_of_day_distribution (hour buckets)
- geo_distribution (call origin regions)
- error_rate (4xx/5xx ratio)
- new_resource_access (boolean: accessing resources not seen in baseline)
- cross_tenant_attempts (boolean: attempting to access other tenants)
```

**Anomaly trigger → Incident Response:**
1. Behavioral engine flags deviation (score > threshold)
2. Notification service fires webhook / PagerDuty / Slack alert
3. If auto-remediate policy active: credential revoked, ServiceNow ticket created
4. SOC team sees full behavioral timeline in dashboard

### 4.5 JIT Access Service

**Flow:**
1. AI agent (or human) requests temporary credential via AgentGuard API
2. Policy engine evaluates request against least-privilege rules
3. If approved: sensor creates scoped, time-bound credential in cloud provider
4. Credential injected into requesting context via Vault dynamic secrets or direct API
5. Auto-expiry: credential revoked at TTL (default 1h, configurable per policy)
6. Full audit trail written to append-only audit log

**JIT Credential Types:** AWS IAM role sessions (STS AssumeRole), Azure managed identity tokens, GCP Workload Identity Federation tokens, short-lived GitHub OIDC tokens.

### 4.6 Integration Hub

Connector registry pattern — each integration is a plugin implementing a standard interface:

```python
class IntegrationConnector(Protocol):
    def test_connection(self) -> ConnectionStatus: ...
    def push_alert(self, alert: Alert) -> None: ...
    def create_ticket(self, incident: Incident) -> TicketRef: ...
    def sync_identities(self) -> list[ExternalIdentity]: ...
```

**MVP Integrations:** Slack, PagerDuty, Jira, Splunk (webhook/syslog)
**V2 Integrations:** CyberArk PAM, HashiCorp Vault, Okta, ServiceNow, Microsoft Sentinel

---

## 5. Multi-Tenancy Architecture

### Data Isolation Strategy: Schema-per-Tenant with RLS

```sql
-- Tenant provisioning creates a dedicated schema
CREATE SCHEMA tenant_{tenant_id};

-- All tables exist within tenant schema
SET search_path TO tenant_{tenant_id};
CREATE TABLE nhi_identities (...);
CREATE TABLE risk_scores (...);
CREATE TABLE policy_rules (...);
CREATE TABLE audit_log (...);  -- append-only, no UPDATE/DELETE grants

-- Row-Level Security as defense-in-depth
ALTER TABLE nhi_identities ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON nhi_identities
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

**Tenant context flow:** JWT → FastAPI middleware extracts `tenant_id` → set as PostgreSQL session variable → RLS enforces isolation at DB layer even if application bug bypasses schema routing.

### Tenant Tiers and Data Residency

| Tier | Data Plane | Control Plane | Encryption |
|------|-----------|---------------|-----------|
| Starter | AgentGuard VPC | AgentGuard | Shared KMS key |
| Professional | AgentGuard VPC | AgentGuard | Tenant-specific KMS key |
| Enterprise | Customer VPC (hybrid) | AgentGuard | Customer-managed KMS |
| On-Prem | Customer VPC | Customer VPC | Customer-managed |

### Hybrid Deployment Architecture

For hybrid customers, the sensor runs as a Kubernetes deployment in the customer's cloud account:

```yaml
# Helm values for customer deployment
agentguard-sensor:
  controlPlaneEndpoint: "https://api.agentguard.io"  # AgentGuard SaaS
  tenantId: "{{ customer_tenant_id }}"
  authToken: "{{ sensor_auth_token }}"               # Short-lived, rotated automatically
  dataRetention: "local"                             # No raw IAM data leaves VPC
  scanSchedule: "0 */4 * * *"                        # Every 4 hours
  rotationEnabled: true
  providers:
    aws:
      roleArn: "arn:aws:iam::ACCOUNT:role/AgentGuardScanRole"
    azure:
      clientId: "{{ sp_client_id }}"
    gcp:
      serviceAccountEmail: "agentguard@project.iam.gserviceaccount.com"
```

**What crosses the boundary:**
- ✅ Metadata (identity names, types, last-used timestamps, risk scores)
- ✅ Behavioral event summaries (aggregated, not raw API logs)
- ✅ Policy evaluation results
- ❌ Actual credential values (never leave customer VPC)
- ❌ Raw CloudTrail/audit logs (summarized locally, only signals sent)

---

## 6. Cloud Scanner Specifications

Each scanner is a stateless Python class implementing the `BaseConnector` interface. Scans are idempotent — running twice produces the same result.

### Minimum IAM Permissions Required (AWS example)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:List*", "iam:Get*",
        "iam:GenerateCredentialReport",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "organizations:ListAccounts",
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    }
  ]
}
```
Rotation adds: `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `secretsmanager:RotateSecret`

### Scanner Output: Normalized NHI Records
All four cloud scanners output to the canonical `NHIIdentity` schema. Provider-specific data goes into `metadata`. This normalization is the key abstraction — the risk engine, policy engine, and dashboard are provider-agnostic.

### Scan Scheduling
- **Full scan:** Every 4 hours (configurable per tenant)
- **Incremental scan:** Triggered by cloud provider events (CloudTrail, Azure Monitor, GCP Audit Logs) via EventBridge/Event Grid rules — near real-time for high-risk events
- **On-demand scan:** API endpoint `POST /v1/scans` for manual trigger

---

## 7. Security Architecture

### Authentication & Authorization
- **User auth:** Clerk (OIDC provider) — handles SSO/SAML for enterprise, MFA, session management
- **API auth:** Short-lived JWTs (15min expiry) + refresh token rotation
- **Sensor auth:** Mutual TLS + sensor-specific service tokens (30-day rotation)
- **Internal service auth:** mTLS between all internal services

### RBAC Model
```
Tenant Owner → full access including billing, user management
CISO / Security Admin → read/write all resources, approve policies
Security Analyst → read all, can create/acknowledge alerts
Auditor → read-only, compliance reports only
Integration Service Account → write behavioral telemetry only
```

### Audit Logging
Every write operation (policy change, rotation, revocation, JIT grant) produces an immutable audit record:
```python
class AuditEvent:
    id: UUID
    tenant_id: UUID
    actor_type: Literal["USER", "SENSOR", "POLICY", "SYSTEM"]
    actor_id: str
    action: str              # "ROTATED_CREDENTIAL", "REVOKED_CREDENTIAL", etc.
    resource_type: str
    resource_id: str
    outcome: Literal["SUCCESS", "FAILURE"]
    reason: str
    timestamp: datetime
    ip_address: str | None
    metadata: dict
```
Audit log is append-only at the database level (no UPDATE/DELETE privileges on the table). Exportable as SIEM-ready JSON/CEF.

### Secrets Management
- All cloud connector credentials stored in HashiCorp Vault (or AWS Secrets Manager for SaaS tier)
- No credentials in environment variables or config files
- Sensor auth tokens are short-lived and rotated by the control plane automatically

---

## 8. Technology Stack

| Layer | Technology | Rationale |
|-------|-----------|-----------|
| Frontend | Next.js 15 (App Router) + TypeScript | SSR for fast dashboard loads, App Router for streaming |
| UI Components | shadcn/ui + Tailwind CSS | Accessible, customizable, enterprise feel |
| Charts | Recharts + D3 (behavioral timelines) | Flexibility for custom behavioral visualizations |
| API Framework | FastAPI (Python 3.12) | Async, auto-OpenAPI docs, native Pydantic validation |
| ORM | SQLAlchemy 2.0 (async) | Mature, supports schema-per-tenant |
| Policy Evaluation | Open Policy Agent (OPA) + Rego | Industry standard, auditable |
| Inventory DB | PostgreSQL 16 (RDS) | Relational, tenant schema isolation, RLS |
| Behavioral DB | ClickHouse (Cloud) | Columnar, best-in-class for time-series analytics |
| Cache | Redis (ElastiCache) | Session store, JIT token tracking, rate limiting |
| Message Queue | AWS SQS + SNS | Scan job queuing, event fanout, dead letter queues |
| ML / Anomaly Detection | scikit-learn (Isolation Forest) | Interpretable, no GPU required, fast inference |
| Auth | Clerk | OIDC, SAML SSO, MFA — enterprise-ready out of box |
| Secrets | HashiCorp Vault | Industry standard for secrets management |
| Container Orchestration | Kubernetes (EKS) | Sensor runs in customer K8s, ops consistency |
| IaC | Terraform + Terragrunt | Multi-environment, module reuse |
| Sensor Packaging | Helm Chart | Standard K8s app distribution |
| CI/CD | GitHub Actions + ArgoCD | GitOps for control plane, Helm for sensors |
| Observability | OpenTelemetry → Datadog | Distributed tracing across control/data plane |
| Frontend Hosting | Vercel | Zero-config deployment, CDN, preview environments |

---

## 9. Database Schema (Key Tables)

```sql
-- Global tables (in public schema)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    tier TEXT NOT NULL CHECK (tier IN ('starter','professional','enterprise','onprem')),
    deployment_mode TEXT NOT NULL CHECK (deployment_mode IN ('saas','hybrid')),
    kms_key_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Per-tenant schema (created at tenant provisioning)
-- Example: tenant_550e8400_e29b_41d4_a716_446655440000

CREATE TABLE nhi_identities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    external_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,         -- API_KEY, SERVICE_ACCOUNT, OAUTH_TOKEN, BOT, AGENT_CREDENTIAL
    provider TEXT NOT NULL,     -- AWS, AZURE, GCP, GITHUB, GITLAB
    classification TEXT,        -- AI_AGENT, CICD, INTEGRATION, HUMAN_PROXY, UNKNOWN
    owner_email TEXT,
    status TEXT DEFAULT 'ACTIVE',
    created_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_rotated_at TIMESTAMPTZ,
    last_scanned_at TIMESTAMPTZ DEFAULT NOW(),
    raw_metadata JSONB,
    UNIQUE(provider, external_id)
);

CREATE TABLE risk_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nhi_id UUID REFERENCES nhi_identities(id) ON DELETE CASCADE,
    score NUMERIC(5,2) NOT NULL CHECK (score BETWEEN 0 AND 100),
    factors JSONB NOT NULL,     -- [{factor, weight, value, contribution}]
    computed_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE policy_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    description TEXT,
    yaml_definition TEXT NOT NULL,
    compiled_rego TEXT,
    enforcement_mode TEXT DEFAULT 'MONITOR',
    enabled BOOLEAN DEFAULT TRUE,
    compliance_mappings TEXT[],
    created_by TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE policy_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    nhi_id UUID REFERENCES nhi_identities(id),
    policy_id UUID REFERENCES policy_rules(id),
    detected_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    resolution TEXT,            -- AUTO_ROTATED, MANUALLY_RESOLVED, EXEMPTED
    metadata JSONB
);

CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_type TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    outcome TEXT NOT NULL,
    reason TEXT,
    ip_address INET,
    metadata JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
    -- NO UPDATE, NO DELETE — enforced via role grants
);

CREATE TABLE jit_grants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    requester_id TEXT NOT NULL,
    nhi_id UUID REFERENCES nhi_identities(id),
    scope JSONB NOT NULL,       -- What permissions are granted
    reason TEXT NOT NULL,
    approved_by TEXT,
    issued_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    status TEXT DEFAULT 'ACTIVE'
);
```

---

## 10. Implementation Phases

### Phase 0: Foundation (Weeks 1–2)
- [ ] Initialize monorepo (turborepo or flat monorepo)
- [ ] Set up Next.js 15 app with Clerk auth (web dashboard skeleton)
- [ ] Set up FastAPI app with tenant middleware, OpenAPI spec
- [ ] Provision PostgreSQL (RDS) with schema-per-tenant migration system (Alembic)
- [ ] Tenant provisioning API + schema automation
- [ ] GitHub Actions CI pipeline (lint, type-check, test)
- [ ] Terraform: VPC, EKS cluster, RDS, Redis, SQS, secrets in Vault

### Phase 1: Discovery Engine (Weeks 3–5)
- [ ] `BaseConnector` abstract class and normalized output schema
- [ ] AWS IAM scanner (IAM users, roles, access keys, service accounts)
- [ ] AWS Secrets Manager scanner
- [ ] Azure Entra ID scanner (service principals, app registrations)
- [ ] Azure Key Vault scanner
- [ ] GCP IAM scanner (service accounts, keys)
- [ ] GCP Secret Manager scanner
- [ ] GitHub scanner (Actions secrets, GITHUB_TOKEN usage, OAuth apps)
- [ ] Scan scheduler (SQS-based, per-tenant scan jobs)
- [ ] Sensor packaging as Docker image + Helm chart

### Phase 2: Inventory & Risk MVP (Weeks 6–8)
- [ ] Inventory service CRUD API
- [ ] Identity classification algorithm (rule-based v1: name patterns + permission analysis)
- [ ] Risk scoring engine (deterministic, all 5 factors)
- [ ] Stale credential detection (unused 30+ days, never rotated, no owner)
- [ ] Web dashboard: inventory table with search/filter, risk score cards
- [ ] Basic policy engine (OPA integration, YAML DSL → Rego compiler)
- [ ] Pre-built policies: stale keys, admin privileges, unowned accounts
- [ ] Compliance report generation (SOC 2, NIST 800-53 templates)

### Phase 3: Rotation & Policies (Weeks 9–12)
- [ ] AWS IAM access key rotation (create new → distribute → delete old)
- [ ] Azure app secret rotation
- [ ] GCP service account key rotation
- [ ] Rotation orchestrator (approval workflow → sensor execution → verification)
- [ ] Policy violation dashboard + alerting (Slack, PagerDuty)
- [ ] Policy enforcement modes (monitor → alert → enforce)
- [ ] Audit log UI

### Phase 4: V2 Features (Months 4–8)
- [ ] Behavioral telemetry pipeline (gRPC emitter → Kafka → ClickHouse)
- [ ] Baseline computation (14-day learning period per NHI)
- [ ] Isolation Forest anomaly detection model
- [ ] Anomaly alert UI (behavioral timeline, deviation explanation)
- [ ] Least-privilege recommender (actual vs. granted permissions gap analysis)
- [ ] JIT access service (full flow: request → policy eval → credential issue → expiry)
- [ ] Agent workflow topology map (visual graph of agent → service → credential relationships)
- [ ] Integration hub: CyberArk, HashiCorp Vault, Okta connectors
- [ ] Incident response playbooks (automated multi-step responses)
- [ ] Multi-cloud CIEM: cross-cloud privilege escalation path analysis

---

## 11. Go-to-Market Architecture Considerations

### Selling to Multiple Clients: What Makes This Defensible
1. **Agentless scanning** — no code changes required, 30-minute deployment
2. **Hybrid deployment** — data never leaves customer boundary (closes regulated industry deals)
3. **Pre-built compliance reports** — CISO can show auditors immediately, no custom work
4. **Progressive enforcement** — start in Monitor mode, build trust, then enable Enforce
5. **Existing tool integration** — not a rip-and-replace, enhances CyberArk/Vault investments

### Pricing Model Architecture
- **Starter** ($2,500/mo): Up to 5,000 NHIs, SaaS, 2 cloud providers, Monitor mode only
- **Professional** ($8,000/mo): Up to 50,000 NHIs, SaaS, all providers, Enforce + JIT
- **Enterprise** (custom, $50K–$250K ARR): Unlimited NHIs, hybrid deployment, behavioral AI, dedicated support

Pricing metric: **NHI count** (like seat count for human IAM). Scales naturally with customer growth.

---

## 12. Verification Plan

**MVP validation (end-to-end):**
1. Provision a new tenant → verify isolated schema created in PostgreSQL
2. Configure AWS connector with read-only IAM role → trigger scan → verify NHIs appear in inventory
3. Create a stale credential policy (30-day unused) → verify violation flagged within scan cycle
4. Trigger rotation on a test IAM access key → verify old key deleted, new key active in AWS
5. Generate SOC 2 compliance report → verify NHI-related controls populated correctly
6. Deploy sensor via Helm in a local K8s cluster → verify it connects to control plane and reports back

**Security validation:**
- Attempt cross-tenant data access via API → verify 403/tenant isolation holds
- Verify audit log has no UPDATE/DELETE permissions at DB level
- Pen test: inject malicious policy YAML → verify OPA compilation rejects unsafe input

**Scale validation:**
- Load test inventory API with 100,000 NHIs per tenant → verify P99 < 500ms
- Simulate 50 concurrent tenants scanning simultaneously → verify no cross-tenant data bleed

---

## Critical Files to Create First

1. `apps/api/core/database.py` — tenant schema routing (the foundation everything else sits on)
2. `apps/sensor/connectors/base.py` — the abstraction all 4 cloud connectors implement
3. `packages/nhi-schema/models.py` — canonical NHI data model (shared across web, api, sensor)
4. `apps/api/core/auth.py` — Clerk JWT validation + tenant extraction middleware
5. `infrastructure/terraform/modules/control-plane/main.tf` — the infra foundation
6. `apps/web/app/dashboard/inventory/page.tsx` — first user-facing screen
