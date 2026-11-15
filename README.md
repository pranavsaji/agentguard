# AgentGuard

**Non-Human Identity (NHI) Governance for the Agentic AI Era**

AgentGuard is a multi-tenant SaaS platform that discovers, scores, governs, and rotates non-human cloud and Git identities — API keys, service accounts, OAuth tokens, bot credentials, and AI agent identities — across AWS, Azure, GCP, and GitHub. It is purpose-built for the identity sprawl created by AI agents and automated workloads that existing IAM tools (Okta, CyberArk, SailPoint) were never designed to handle.

---

## Table of Contents

- [What Problem It Solves](#what-problem-it-solves)
- [Architecture Overview](#architecture-overview)
- [Repository Structure](#repository-structure)
- [Core Capabilities](#core-capabilities)
- [Technology Stack](#technology-stack)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Web Dashboard](#web-dashboard)
  - [API (Control Plane)](#api-control-plane)
  - [Sensor (Data Plane)](#sensor-data-plane)
- [Environment Variables](#environment-variables)
- [Database Schema](#database-schema)
- [Multi-Tenancy Model](#multi-tenancy-model)
- [Hybrid Deployment](#hybrid-deployment)
- [API Reference](#api-reference)
- [Risk Scoring](#risk-scoring)
- [Policy Engine](#policy-engine)
- [Cloud Scanner Permissions](#cloud-scanner-permissions)
- [Roadmap](#roadmap)
- [Pricing Model](#pricing-model)

---

## What Problem It Solves

Enterprise AI deployment is creating unmanaged NHI sprawl at a pace existing IAM tools cannot address — they were built for human users. Every AI agent, CI/CD pipeline, and microservice integration mints new credentials that are:

- Never rotated (or rotated inconsistently)
- Granted far more permissions than actually used
- Owned by no one after the engineer who created them leaves
- Invisible to compliance auditors

AgentGuard provides a single governance layer: discover all NHIs across every cloud, score their risk, enforce policies, and automate rotation — without touching application code.

---

## Architecture Overview

AgentGuard uses a **two-plane architecture** that makes hybrid deployment (scanner inside the customer's VPC, control plane in AgentGuard cloud) a first-class design constraint — and a security selling point, since raw IAM data never leaves the customer boundary.

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLIENT LAYER                             │
│          Web Dashboard  │  REST API  │  CLI  │  Webhooks         │
└───────────────────────────┬─────────────────────────────────────┘
                            │ HTTPS + JWT (Clerk OIDC)
┌───────────────────────────▼─────────────────────────────────────┐
│                  CONTROL PLANE (AgentGuard SaaS)                 │
│                                                                  │
│   Inventory Service  │  Risk Engine  │  Policy Engine (OPA)      │
│   JIT Access Service │  Behavioral Engine │  Integration Hub     │
│                                                                  │
│         PostgreSQL  │  ClickHouse  │  Redis  │  SQS/Kafka        │
└───────────────────────────┬─────────────────────────────────────┘
                            │ Encrypted gRPC (mTLS)
┌───────────────────────────▼─────────────────────────────────────┐
│             DATA PLANE (Customer VPC or AgentGuard VPC)          │
│                                                                  │
│   AWS Scanner │ Azure Scanner │ GCP Scanner │ GitHub Scanner      │
│   Rotation Agent                │  Telemetry Collector           │
└─────────────────────────────────────────────────────────────────┘
```

**What crosses the plane boundary:**
- Metadata (identity names, types, last-used timestamps, risk scores) ✅
- Behavioral event summaries (aggregated, not raw API logs) ✅
- Policy evaluation results ✅
- Actual credential values (never leave customer VPC) ❌
- Raw CloudTrail / audit logs (summarized locally; only signals sent) ❌

---

## Repository Structure

```
agentguard/
├── apps/
│   ├── web/                        # Next.js 16 App Router dashboard
│   │   ├── src/app/dashboard/      # Inventory, Risk, Policy, JIT views
│   │   ├── src/components/         # shadcn/ui primitives + domain components
│   │   └── src/lib/
│   │       ├── api-client.ts       # Typed fetch client (Bearer token via Clerk)
│   │       └── auth.ts             # Clerk configuration
│   │
│   ├── api/                        # FastAPI control plane
│   │   ├── main.py                 # App entrypoint; router registration; DDL bootstrap
│   │   ├── core/
│   │   │   ├── config.py           # pydantic-settings (all env vars)
│   │   │   ├── database.py         # Async SQLAlchemy; tenant schema routing
│   │   │   ├── auth.py             # Clerk JWT validation; AuthContext extraction
│   │   │   └── events.py           # SQS publish helpers (scan / rotation events)
│   │   ├── domains/
│   │   │   ├── inventory/          # NHI catalog: list, get, upsert, revoke, rotate
│   │   │   ├── tenants/            # Tenant CRUD + schema provisioning
│   │   │   ├── policy/             # YAML DSL → Rego compiler; OPA eval; violations
│   │   │   └── jit/                # JIT grant lifecycle
│   │   └── workers/
│   │       ├── scan_scheduler.py   # SQS consumer; triggers sensor scans
│   │       └── rotation_orchestrator.py
│   │
│   └── sensor/                     # Data plane sensor (deployed in customer VPC)
│       ├── main.py                 # Async scan loop; POSTs results to control plane
│       ├── connectors/
│       │   ├── base.py             # BaseConnector interface + ScanResult type
│       │   ├── aws/iam_scanner.py
│       │   ├── azure/entra_scanner.py
│       │   ├── gcp/iam_scanner.py
│       │   └── github/secrets_scanner.py
│       └── rotation/
│           ├── aws_rotator.py
│           ├── azure_rotator.py
│           └── gcp_rotator.py
│
├── packages/
│   ├── nhi-schema/                 # Shared canonical NHI data model (Pydantic)
│   │   └── models.py               # NHIIdentity, RiskScore, PolicyRule, AuditEvent, …
│   └── risk-engine/                # Deterministic risk scoring library
│       ├── scorer.py               # compute_risk_score(), batch_score()
│       └── factors.py              # Factor weights and signal definitions
│
├── infrastructure/                 # Terraform + Helm (planned)
│   ├── terraform/modules/
│   │   ├── control-plane/          # EKS, RDS, ClickHouse, Redis, SQS, Vault
│   │   └── sensor/                 # Helm chart + IAM roles for customer deployment
│   └── helm/agentguard-sensor/
│
├── workflows/                      # Operational SOPs
│   ├── onboard_tenant.md
│   ├── scan_cloud_env.md
│   ├── rotate_credential.md
│   └── investigate_anomaly.md
│
├── tools/                          # Utility scripts
│   └── check_duplicates.py
│
└── ARCHITECTURE.md                 # Full product and system design specification
```

---

## Core Capabilities

### NHI Inventory
Single source of truth for all non-human identities. Every discovered credential is normalized into a canonical `NHIIdentity` record regardless of which cloud it came from. Fields include `type` (API_KEY, SERVICE_ACCOUNT, OAUTH_TOKEN, BOT, AGENT_CREDENTIAL), `provider` (AWS, AZURE, GCP, GITHUB), `classification` (AI_AGENT, CICD, INTEGRATION, HUMAN_PROXY), `owner_email`, `status` (ACTIVE, STALE, ORPHANED, REVOKED), and full `permissions` list.

### Risk Scoring
Deterministic, auditable 0–100 scoring. No black boxes — every score ships a `factors` array that explains each contribution for auditors.

| Factor | Weight | Signal |
|--------|--------|--------|
| Over-permission ratio | 30% | Granted permissions ÷ used permissions (last 90 days) |
| Credential age | 20% | Days since last rotation vs. policy maximum |
| Staleness | 20% | Days since last use (never used = maximum risk) |
| Exposure surface | 15% | Number of services/APIs the credential can reach |
| Blast radius | 15% | Privilege level × account scope |

Scores are recomputed asynchronously on: scan completion, usage event received, policy change, or manual trigger.

### Policy Engine
YAML-based policy DSL compiled to [OPA Rego](https://www.openpolicyagent.org/) internally. Users write human-readable policies; OPA handles evaluation.

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

Enforcement modes: `MONITOR` → `ALERT` → `ENFORCE` → `AUTO_REMEDIATE`.

### Credential Rotation
Sensor-executed rotations approved upstream: create new credential → distribute → delete old → verify. Supported: AWS IAM access keys, Azure app secrets, GCP service account keys.

### JIT Access
1. AI agent (or human) requests a temporary credential via AgentGuard API
2. Policy engine evaluates against least-privilege rules
3. If approved: sensor creates scoped, time-bound credential in cloud provider
4. Credential injected via Vault dynamic secrets or direct API
5. Auto-expiry at TTL (default 1 hour, configurable per policy)
6. Full audit trail written to append-only log

### Behavioral Anomaly Detection (V2)
Telemetry streams from sensor → ClickHouse → Isolation Forest model detects deviations from each NHI's learned 14-day baseline. Signals include: API call rate, unique endpoints, data egress bytes, time-of-day distribution, geo distribution, error rate, new resource access, cross-tenant attempts.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 16 (App Router), React 19, TypeScript, Tailwind CSS 4 |
| UI Components | shadcn/ui, Lucide icons, Recharts |
| Auth | Clerk (OIDC, SAML SSO, MFA) |
| API | FastAPI (Python 3.12), uvicorn, Pydantic v2, pydantic-settings |
| ORM | SQLAlchemy 2.0 (async) + asyncpg |
| Policy Evaluation | Open Policy Agent (OPA) + Rego |
| Inventory DB | PostgreSQL 16 — schema-per-tenant + RLS |
| Behavioral DB | ClickHouse — columnar time-series analytics |
| Cache | Redis — sessions, JIT token tracking, rate limiting |
| Message Queue | AWS SQS + SNS — scan job queuing, event fanout |
| ML / Anomaly | scikit-learn (Isolation Forest) |
| Cloud SDKs | boto3 (AWS), Azure SDK / msgraph (Azure), google-cloud (GCP), PyGithub |
| Secrets | HashiCorp Vault / AWS Secrets Manager |
| Container Orchestration | Kubernetes (EKS), Helm |
| IaC | Terraform + Terragrunt |
| CI/CD | GitHub Actions + ArgoCD |
| Observability | OpenTelemetry → Datadog |
| Frontend Hosting | Vercel |

---

## Getting Started

### Prerequisites

- Node.js 20+ and npm
- Python 3.12+
- PostgreSQL 16 (local or RDS)
- (Optional) Redis, OPA server, AWS SQS queues for full functionality

### Web Dashboard

```bash
cd apps/web
npm install
npm run dev
```

The app starts at `http://localhost:3000`. Set `NEXT_PUBLIC_API_URL` to point at the API server.

**Required environment variables for the web app:**

```bash
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY=pk_test_...
CLERK_SECRET_KEY=sk_test_...
```

### API (Control Plane)

Install shared packages and the API in editable mode:

```bash
# From the repo root
pip install -e packages/nhi-schema
pip install -e packages/risk-engine
pip install -e apps/api
```

Start the server:

```bash
cd apps/api
uvicorn api.main:app --reload --port 8000
```

The API auto-bootstraps the `public.tenants` table on first start. Interactive docs are available at `http://localhost:8000/docs`.

**Required environment variables for the API:**

```bash
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/agentguard

# Clerk JWT verification
CLERK_PEM_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----\n..."

# Optional — SQS for async workers
SQS_SCAN_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/...
SQS_ROTATION_QUEUE_URL=https://sqs.us-east-1.amazonaws.com/...

# Optional — OPA for policy evaluation
OPA_URL=http://localhost:8181

# Optional — Redis
REDIS_URL=redis://localhost:6379
```

### Sensor (Data Plane)

Install the sensor:

```bash
pip install -e packages/nhi-schema
pip install -e apps/sensor
```

Run the scan loop:

```bash
cd apps/sensor
python -m sensor.main
```

The sensor runs a configurable scan loop (default: every 4 hours), normalizes discovered identities into `NHIIdentity` records, and POSTs results to the control plane.

---

## Environment Variables

### Sensor

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENTGUARD_CONTROL_PLANE_URL` | Control plane API base URL | `http://localhost:8000` |
| `AGENTGUARD_SENSOR_TOKEN` | Bearer token for authenticating to the API | — |
| `AGENTGUARD_TENANT_ID` | Tenant UUID this sensor belongs to | — |
| `ENABLED_PROVIDERS` | Comma-separated list: `aws,azure,gcp,github` | — |
| `SCAN_INTERVAL_SECONDS` | Seconds between full scans | `14400` (4h) |
| `AWS_ACCESS_KEY_ID` | AWS credentials for IAM scanner | — |
| `AWS_SECRET_ACCESS_KEY` | — | — |
| `AWS_DEFAULT_REGION` | — | `us-east-1` |
| `AZURE_TENANT_ID` | Azure AD tenant ID | — |
| `AZURE_CLIENT_ID` | Service principal client ID | — |
| `AZURE_CLIENT_SECRET` | — | — |
| `GCP_PROJECT_ID` | GCP project to scan | — |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to GCP service account JSON | — |
| `GITHUB_TOKEN` | GitHub PAT with `admin:org` and `secrets` scope | — |
| `GITHUB_ORG` | GitHub organization name | — |

---

## Database Schema

AgentGuard uses **schema-per-tenant** isolation in PostgreSQL. One `public.tenants` table is shared; every other table lives in a dedicated `tenant_<uuid>` schema provisioned automatically at tenant onboarding.

**Global:**
```sql
CREATE TABLE public.tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    tier TEXT NOT NULL,              -- starter | professional | enterprise | onprem
    deployment_mode TEXT NOT NULL,   -- saas | hybrid
    kms_key_id TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

**Per-tenant (created in `tenant_<uuid>` schema):**

- `nhi_identities` — canonical NHI records with `UNIQUE(provider, external_id)`
- `risk_scores` — scored snapshots per NHI; `factors` JSONB for explainability
- `policy_rules` — YAML + compiled Rego; `enforcement_mode`; `compliance_mappings`
- `policy_violations` — violation events with resolution tracking
- `jit_grants` — JIT credential lifecycle with TTL and `expires_at`
- `audit_log` — **append-only** (no UPDATE/DELETE privileges granted); full actor/action/outcome trail

Row-Level Security is enabled on all per-tenant tables as a defense-in-depth layer even when schema routing is correct:

```sql
CREATE POLICY tenant_isolation ON nhi_identities
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

---

## Multi-Tenancy Model

**Tenant context flow:**
1. Request arrives with Clerk JWT
2. FastAPI `auth.py` extracts `tenant_id` and `role` from `public_metadata`
3. `tenant_session()` sets `SET LOCAL search_path TO tenant_<uuid>` and `SET LOCAL app.tenant_id = '<uuid>'`
4. All ORM queries hit the tenant's schema; RLS enforces the same isolation at the DB layer

**RBAC roles:**

| Role | Permissions |
|------|-------------|
| Tenant Owner | Full access including billing and user management |
| CISO / Security Admin | Read/write all resources; approve policies |
| Security Analyst | Read all; create and acknowledge alerts |
| Auditor | Read-only; compliance reports only |
| Integration Service Account | Write behavioral telemetry only |

**Tenant tiers:**

| Tier | Sensor Location | Encryption |
|------|----------------|-----------|
| Starter | AgentGuard VPC | Shared KMS key |
| Professional | AgentGuard VPC | Tenant-specific KMS key |
| Enterprise | Customer VPC (hybrid) | Customer-managed KMS |
| On-Prem | Customer VPC | Customer-managed |

---

## Hybrid Deployment

For Enterprise customers, the sensor runs as a Kubernetes Deployment inside the customer's cloud account and connects outbound to the AgentGuard control plane via mTLS.

```yaml
# Example Helm values
agentguard-sensor:
  controlPlaneEndpoint: "https://api.agentguard.io"
  tenantId: "{{ customer_tenant_id }}"
  authToken: "{{ sensor_auth_token }}"
  dataRetention: "local"               # No raw IAM data leaves VPC
  scanSchedule: "0 */4 * * *"          # Every 4 hours
  rotationEnabled: true
  providers:
    aws:
      roleArn: "arn:aws:iam::ACCOUNT:role/AgentGuardScanRole"
    azure:
      clientId: "{{ sp_client_id }}"
    gcp:
      serviceAccountEmail: "agentguard@project.iam.gserviceaccount.com"
```

Sensor auth tokens are short-lived and rotated automatically by the control plane.

---

## API Reference

The FastAPI server generates interactive OpenAPI docs at `/docs`.

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/identities` | Paginated, filterable NHI inventory |
| `GET` | `/v1/identities/{id}` | Full NHI detail with permission tree |
| `POST` | `/v1/identities/{id}/rotate` | Queue a credential rotation |
| `POST` | `/v1/identities/{id}/revoke` | Immediate revocation |
| `GET` | `/v1/identities/{id}/activity` | Behavioral timeline |
| `POST` | `/v1/identities/scans` | Trigger an on-demand scan |
| `GET` | `/v1/policies` | List policy rules |
| `POST` | `/v1/policies` | Create a YAML policy rule |
| `GET` | `/v1/policies/{id}/violations` | Violations for a policy |
| `GET` | `/v1/jit` | List JIT grants |
| `POST` | `/v1/jit` | Request a JIT credential |
| `DELETE` | `/v1/jit/{id}` | Revoke a JIT grant |
| `POST` | `/v1/tenants` | Create a tenant + provision schema |
| `GET` | `/v1/tenants/me` | Get current tenant info |
| `GET` | `/health` | Health check |

All endpoints (except `/health` and `POST /v1/tenants`) require a `Bearer <JWT>` header. The JWT is issued by Clerk and must contain `tenant_id` and `role` in its `public_metadata` claim.

---

## Risk Scoring

The `packages/risk-engine` library is provider-agnostic and can be called directly:

```python
from risk_engine.scorer import compute_risk_score
from nhi_schema.models import NHIIdentity

identity: NHIIdentity = ...
score = compute_risk_score(identity)
# score.value → float 0–100
# score.factors → list of {factor, weight, value, contribution, remediation}
```

Batch scoring:

```python
from risk_engine.scorer import batch_score
scores = batch_score(identities)  # list[NHIIdentity] → list[RiskScore]
```

---

## Policy Engine

Policies are written in AgentGuard's YAML DSL. On `POST /v1/policies`, the control plane compiles them to Rego and stores both representations. Evaluation is delegated to OPA.

```yaml
name: no-admin-api-keys
description: No API key should have admin-level permissions
applies_to:
  types: [API_KEY]
  providers: [AWS, AZURE, GCP]
condition:
  permission_level: { eq: "ADMIN" }
action: ALERT
severity: CRITICAL
enforcement_mode: ENFORCE
compliance_mappings:
  - SOC2_CC6.3
  - NIST_AC-6
```

`action` values: `FLAG`, `ALERT`, `AUTO_ROTATE`, `REVOKE`  
`enforcement_mode` values: `MONITOR`, `ALERT`, `ENFORCE`, `AUTO_REMEDIATE`

---

## Cloud Scanner Permissions

Scanners are read-only by default. Rotation requires additional write permissions.

**AWS — minimum read-only policy:**
```json
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
```

Rotation adds: `iam:CreateAccessKey`, `iam:DeleteAccessKey`, `secretsmanager:RotateSecret`

For Azure and GCP, equivalent read-only roles are:
- **Azure:** `Reader` + `Key Vault Reader` on the relevant subscriptions
- **GCP:** `roles/iam.securityReviewer` + `roles/secretmanager.viewer`

---

## Roadmap

| Phase | Scope | Status |
|-------|-------|--------|
| 0 — Foundation | Monorepo, Next.js + Clerk, FastAPI + tenant middleware, PostgreSQL schema automation | ✅ In progress |
| 1 — Discovery Engine | All four cloud scanners, SQS-based scan scheduler, Helm packaging | ✅ In progress |
| 2 — Inventory & Risk MVP | Risk scoring, stale detection, OPA policy engine, compliance reports, web dashboard | ✅ In progress |
| 3 — Rotation & Policies | AWS/Azure/GCP rotation orchestrator, policy enforcement modes, audit log UI | 🔲 Planned |
| 4 — V2 Features | Behavioral telemetry pipeline, anomaly detection, JIT full flow, integration hub, CIEM | 🔲 Planned |

---

## Pricing Model

| Tier | Price | NHI Limit | Cloud Providers | Enforcement |
|------|-------|-----------|----------------|-------------|
| Starter | $2,500/mo | 5,000 | 2 | Monitor only |
| Professional | $8,000/mo | 50,000 | All | Enforce + JIT |
| Enterprise | Custom ($50K–$250K ARR) | Unlimited | All | Behavioral AI + Hybrid |

Pricing metric: **NHI count** — scales naturally with customer growth.

---

## Security Notes

- JWT access tokens are short-lived (15-minute expiry) with refresh token rotation
- Sensor auth tokens are 30-day lived and rotated automatically by the control plane
- No credential values are stored in the control plane — only metadata
- The audit log table has `NO UPDATE / NO DELETE` privileges at the database role level
- Cross-tenant isolation is enforced at both the application layer (schema routing) and the database layer (RLS)

---

## Contributing

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full system design specification, domain service contracts, and verification plan.
