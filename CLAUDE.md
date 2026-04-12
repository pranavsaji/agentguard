# AgentGuard

**Non-Human Identity (NHI) Governance SaaS** — discovers, scores, governs, and rotates API keys, service accounts, OAuth tokens, and AI agent credentials across AWS, Azure, GCP, and GitHub.

## Architecture

Two-plane design: **Control Plane** (AgentGuard-hosted FastAPI + Next.js) and **Data Plane** (sensor deployed in customer VPC or AgentGuard VPC). Raw IAM data never leaves the customer boundary — only metadata and risk scores cross the plane boundary.

```
apps/
  web/        # Next.js 16 + React 19 dashboard (Vercel)
  api/        # FastAPI control plane (Python 3.12)
  sensor/     # Data plane scanner + rotator (Python, K8s)
packages/
  nhi-schema/  # Canonical NHIIdentity Pydantic model (shared)
  risk-engine/ # Deterministic 0–100 risk scorer (shared)
infrastructure/ # Terraform + Helm
.github/
  workflows/
    ci.yml    # lint + test + build on every push
    cd.yml    # deploy to Vercel (web) + EKS placeholder (api) on main
```

## Running Locally

**Web** (`apps/web`):
```bash
npm install && npm run dev   # http://localhost:3000
```
Required env: `NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY`, `CLERK_SECRET_KEY`

**API** (`apps/api`):
```bash
pip install -e packages/nhi-schema packages/risk-engine apps/api
cd apps/api && uvicorn main:app --reload --port 8000
# OpenAPI docs: http://localhost:8000/docs
```
Required env: `DATABASE_URL` (asyncpg), `CLERK_PEM_PUBLIC_KEY`
Optional env: `OPA_URL`, `REDIS_URL`, `SQS_SCAN_QUEUE_URL`, `SQS_ROTATION_QUEUE_URL`, `SENSOR_AUTH_SECRET`, `SLACK_WEBHOOK_URL`, `PAGERDUTY_ROUTING_KEY`

**Sensor** (`apps/sensor`):
```bash
pip install -e packages/nhi-schema apps/sensor
cd apps/sensor && python main.py
```
Required env: `AGENTGUARD_CONTROL_PLANE_URL`, `AGENTGUARD_SENSOR_TOKEN`, `AGENTGUARD_TENANT_ID`, `ENABLED_PROVIDERS`

**Workers** (run as separate processes alongside the API):
```bash
python -m api.workers.scan_scheduler       # dispatches scan jobs
python -m api.workers.rotation_orchestrator # dispatches rotation jobs
python -m api.workers.policy_enforcer      # evaluates policies after each scan
python -m api.workers.risk_recomputer      # recomputes risk scores after each scan
```

## Domain Layout (API)

All domains follow the pattern: `router.py + schemas.py + service.py`.

| Domain | Prefix | What it owns |
|--------|--------|-------------|
| `inventory` | `/v1/identities` | NHI CRUD, rotate, revoke, scan trigger |
| `tenants` | `/v1/tenants` | Tenant provisioning, schema creation |
| `policy` | `/v1/policies` | YAML DSL → OPA Rego, violations |
| `jit` | `/v1/jit/grants` | Time-limited credential grants |
| `risk` | `/v1/risk` | Risk stats, history, top-N, recompute |
| `behavioral` | `/v1/behavioral` | Event ingestion, anomaly detection, baselines |
| `compliance` | `/v1/compliance` | SOC2 / NIST 800-53 / PCI DSS / ISO 27001 reports |
| `integrations` | `/v1/integrations` | Webhooks (Slack/PD/generic), alerts |

**Internal endpoint** (sensor → control plane):
```
POST /v1/internal/scan-results   X-Sensor-Token: <secret>
```
Not in public OpenAPI docs. Accepts `ScanResult`, upserts NHIs, queues risk recompute.

## Key Patterns

**Multi-tenancy**: Schema-per-tenant in PostgreSQL (`tenant_<uuid>` schema) + Row-Level Security. Every request sets `search_path` and `app.tenant_id` via `tenant_session()` in `apps/api/core/database.py`. Never bypass this.

**Auth (user-facing)**: Clerk JWTs carry `tenant_id` and `role` in `public_metadata`. Validated in `apps/api/core/auth.py`. `Auth = Annotated[AuthContext, Depends(get_auth_context)]` is the dependency alias used in all routers.

**Auth (sensor)**: `X-Sensor-Token` header validated against `SENSOR_AUTH_SECRET` env var. Used on behavioral event ingestion and the internal scan-results endpoint.

**Risk scoring**: `compute_risk_score(identity: NHIIdentity)` from `packages/risk-engine/scorer.py`. 5-factor deterministic model. Scores auto-recomputed by `risk_recomputer` worker after every scan.

**Policy engine**: YAML DSL → OPA Rego. **Fail-closed in ENFORCE/AUTO_REMEDIATE mode** (HTTP 503 if OPA unreachable). Fail-open in MONITOR/ALERT mode. `policy_enforcer` worker evaluates all active policies after every scan and records violations.

**Behavioral anomaly detection**: Rule-based (no ML dependency). Compares last-24h auth failure rate, event volume, and service set against the NHI's 14-day baseline stored in `behavioral_baselines`. Baselines require ≥14 days of event data (`warmup_complete = TRUE`).

**Compliance reports**: Derived entirely from existing DB data (policy_violations, nhi_identities, risk_scores, behavioral_events). No separate compliance DB needed. Four frameworks: SOC2, NIST_800_53, PCI_DSS, ISO_27001.

**Notifications**: `send_notification()` in `integrations/service.py` inserts an alert row and fans out to all matching enabled webhooks. Webhook delivery is fire-and-forget (failures are logged, not raised).

**NHI data model**: Canonical schema in `packages/nhi-schema/models.py`. Use this across all three apps — never define a parallel NHI type.

## Database Tables (per-tenant schema)

| Table | Purpose |
|-------|---------|
| `nhi_identities` | Core NHI catalog |
| `risk_scores` | Scored snapshots, append-only |
| `policy_rules` | YAML + compiled Rego |
| `policy_violations` | Violation events with resolution |
| `jit_grants` | Time-limited access grants |
| `audit_log` | Append-only, no UPDATE/DELETE grants |
| `behavioral_events` | Raw activity events from sensor telemetry |
| `behavioral_baselines` | 14-day learned baseline per NHI |
| `integration_webhooks` | External notification endpoints |
| `alerts` | Notification history, acknowledgement state |

All tables have RLS enabled. New tables are provisioned in `apps/api/core/database.py:provision_tenant_schema()`.

## Frontend Pages

| Route | Page |
|-------|------|
| `/dashboard/inventory` | NHI table, filters, rotate/revoke/scan actions |
| `/dashboard/risk` | Severity cards, distribution chart, top-10 risky |
| `/dashboard/policies` | Policy rules, YAML editor modal, violations table |
| `/dashboard/jit` | Active grants, request modal, 30s auto-refresh |
| `/dashboard/compliance` | Framework tabs, score circle, controls table |
| `/dashboard/integrations` | Webhook cards, add-webhook dialog, alerts table |

All pages are `"use client"`, use `useAuth()` from Clerk, and call `apiClient.*` from `src/lib/api-client.ts`.

## CI/CD

| Workflow | Trigger | Jobs |
|----------|---------|------|
| `ci.yml` | Every push + PRs to main | api-test, sensor-install, risk-engine-test, web-lint-build |
| `cd.yml` | Push to main only | deploy-web (Vercel), deploy-api (EKS placeholder) |

Required GitHub secrets for CD: `VERCEL_TOKEN`, `VERCEL_ORG_ID`, `VERCEL_PROJECT_ID`.

## Tech Stack

| | |
|---|---|
| Frontend | Next.js 16.2, React 19, TypeScript, Tailwind CSS, shadcn/ui, Clerk |
| API | FastAPI, SQLAlchemy 2.0 async, Pydantic v2, OPA |
| Databases | PostgreSQL 16 (inventory, schema-per-tenant), ClickHouse (behavioral — config wired, not yet tables), Redis (cache/JIT) |
| Queue | AWS SQS + SNS |
| Sensor clouds | boto3 (AWS), Azure SDK, google-cloud, PyGithub |
| Infra | Terraform, Helm, EKS, Vercel |

## CISO-Relevant Security Properties

- **Fail-closed policy enforcement**: ENFORCE/AUTO_REMEDIATE modes return HTTP 503 if OPA is unreachable rather than silently allowing requests through
- **Append-only audit log**: `audit_log` table has no UPDATE/DELETE grants at the DB role level
- **No credential values in control plane**: Sensor rotates credentials locally; only metadata crosses the plane boundary
- **Schema + RLS isolation**: Cross-tenant data access is blocked at both the application layer (search_path routing) and the DB layer (RLS policies on every table)
- **Sensor auth is separate from user auth**: `X-Sensor-Token` shared secret, not a Clerk JWT, prevents credential confusion
- **Behavioral baselines require warmup**: Anomaly detection only fires after 14 days of data, preventing false-positive floods on new NHIs

## Hooks

A pre-tool-use hook runs `tools/check_duplicates.py` before every Write/Edit. If it blocks, fix the duplicate before proceeding.

## WAT Framework

Operational SOPs in `workflows/`. Execution scripts in `tools/`. When adding automation, follow the same pattern: SOP in `workflows/`, implementation in `tools/`.
