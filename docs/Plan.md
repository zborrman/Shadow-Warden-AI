# Plan.md — Professional Site Build Roadmap
# Shadow Warden AI · v4.11 · Cowork Build

> Phased delivery plan for the five-module professional site:
> Business Community · Cyber Security · Documentation · Settings · Payments.
> Each phase is independently deployable and builds on the previous.

---

## Phase 0 — Foundation (Week 1)

**Goal:** shared infrastructure that all five modules depend on.

| Task | Owner | Output |
|------|-------|--------|
| Docker Compose for site stack (Astro, FastAPI, Postgres, Redis, MinIO, Caddy) | Infra | `docker-compose.site.yml` |
| `Settings(frozen=True)` class with all env vars, pydantic-settings | Backend | `warden/site/settings.py` |
| `EvidenceBucket` + `ScreencastRecorder` wired for site patrol | Backend | `warden/storage/s3.py` + `screencast.py` |
| CI pipeline: lint + type-check + secret-scan + visual-patrol gates | DevOps | `.github/workflows/site-ci.yml` |
| Pre-commit hooks installed (all 7 from Hook.md) | DevOps | `.pre-commit-config.yaml` |
| Base Astro layout: Navbar, Footer, theme tokens, dark mode | Frontend | `site/src/layouts/SiteLayout.astro` |
| Auth layer: OAuth2/OIDC + MFA, session management | Backend | `warden/api/auth.py` |
| Prometheus metrics skeleton + Grafana dashboard | Infra | `grafana/provisioning/site_overview.json` |

**Definition of Done:** `docker-compose.site.yml up` serves a blank site with `/health` returning `200`, patrol runs clean, CI green.

---

## Phase 1 — Business Community (Week 2–3)

**Goal:** authenticated community portal — posts, comments, file sharing, member roles.

### Backend

```
warden/api/community.py       POST /community/posts, GET /community/feed
warden/api/community_files.py POST /community/files/upload (ClamAV + SecretRedactor)
warden/models/community.py    Post, Comment, Member, FileRecord dataclasses
warden/workers/content_filter.py  ARQ job: screenshot → Claude Vision → approve/reject
```

### Frontend (Astro pages)

```
site/src/pages/community/index.astro     Feed + compose
site/src/pages/community/post/[id].astro Post detail + comments
site/src/pages/community/files.astro     File vault
site/src/components/MemberCard.astro
site/src/components/ContentWarning.astro
```

### Key milestones

| Milestone | Acceptance Criteria |
|-----------|---------------------|
| User can post text | Post appears in feed; ContentFilter verdict stored in MinIO |
| File upload | ClamAV + PII scan passes; file accessible only to community members |
| Moderation | Admin can remove post; action logged to `evidence/community/mod-<id>.json` |
| Rate limiting | 101st post/hour returns `429`; Redis key expires correctly |

---

## Phase 2 — Cyber Security Hub (Week 3–4)

**Goal:** public-facing security posture page + internal SOC dashboard.

### Pages

```
site/src/pages/security/index.astro          Public security posture (cert badges, CVE status)
site/src/pages/security/pentest.astro        Pentest findings timeline (redacted for public)
site/src/pages/security/compliance.astro     SOC2 / GDPR / OWASP evidence links
```

### Backend

```
warden/api/security_hub.py    GET /security/posture, GET /security/cve-feed
warden/workers/cve_scanner.py ARQ job: OSV API scan every 6h → findings in MinIO
warden/api/soc_dashboard.py   Internal: circuit breaker state, bypass ratio, heap stats
```

### Integration points

- `WardenHealer` watchdog wired to `soc_dashboard` — auto-publishes health badge.
- CVE findings trigger Slack alert to `#security-ops` and update posture page badge automatically.
- Visual patrol runs nightly on `/security` — Claude Vision prompt: "confirm no critical CVE count is displayed as green when it should be red".

### Key milestones

| Milestone | Acceptance Criteria |
|-----------|---------------------|
| Posture badge auto-updates | Badge colour changes within 15 min of new CVE hit |
| Pentest timeline live | ≥3 closed findings shown with remediation date |
| Internal SOC view | Circuit breaker state and bypass ratio visible, refresh ≤30s |

---

## Phase 3 — Documentation (Week 4–5)

**Goal:** versioned MkDocs site, auto-generated API reference, integrated changelog.

### Structure

```
docs/
├── site-Rule.md        (this project's rules)
├── Hook.md
├── Plan.md
├── api/                Auto-generated from OpenAPI spec
├── guides/             How-to guides for each module
├── architecture/       Diagrams (Mermaid), decision records
└── changelog/          Keep a Changelog format
```

### Build pipeline

```yaml
# CI step
- run: mkdocs build --strict --site-dir site/dist/docs
- run: aws s3 sync site/dist/docs s3://evidence/docs/${{ github.ref_name }}/
```

### Versioning

| Path | Content |
|------|---------|
| `/docs/stable` | Latest release tag |
| `/docs/latest` | `main` branch build |
| `/docs/v4.10` | Archived version |

### Key milestones

| Milestone | Acceptance Criteria |
|-----------|---------------------|
| Auto-generated API ref | All FastAPI routes documented with request/response examples |
| Link check passes | `mkdocs build --strict` exits 0 in CI |
| Evidence snapshot | Each release uploads docs to MinIO with SHA-256 manifest |

---

## Phase 4 — Settings Integration (Week 5–6)

**Goal:** enterprise-settings page fully wired to live backend config, with approval workflow.

### Pages (already exists as static — now wire to API)

```
landing/enterprise-settings.html  →  API calls to /api/config
landing/settings.html             →  API calls to /api/config (user-level)
```

### Backend

```
warden/api/config.py        GET /api/config, POST /api/config (Tier-1 approval gate)
warden/site/approval.py     Redis-backed approval tokens (HMAC-SHA256, 1h TTL)
warden/workers/settings_watcher.py  ARQ: detect config drift, Slack alert
```

### Approval workflow for Tier-1 changes

```
Admin changes ANTHROPIC_API_KEY in UI
  → POST /api/config returns 202 + approval_token
  → Slack message: "Approve change? /approve/<token>"
  → Admin clicks approve
  → Config applied + evidence written to MinIO
  → Container graceful restart scheduled (if required)
```

### Key milestones

| Milestone | Acceptance Criteria |
|-----------|---------------------|
| Settings round-trip | Change threshold in UI → value reads back correctly from /api/config |
| Tier-1 approval | API key change blocked without Slack approval |
| Hot-reload works | Threshold change applies without restart; verified by canary probe |

---

## Phase 5 — Payment Plan (Week 6–7)

**Goal:** Stripe-first subscription flow with MinIO audit trail and fail-open fallback.

### Pages

```
site/src/pages/pricing.astro          Public pricing (mirrors Pricing.astro from landing)
site/src/pages/checkout/[plan].astro  Stripe Checkout session initiation
site/src/pages/billing/index.astro    Customer portal (Stripe Customer Portal redirect)
```

### Backend

```
warden/api/payments.py
  POST /billing/subscribe         Create Stripe Checkout session
  POST /billing/webhook           Stripe webhook receiver (idempotent)
  POST /billing/refund            Admin-only, X-Admin-Key required
  GET  /billing/status            Current plan + addon status for tenant
  POST /billing/addons/grant      Admin grant
  DELETE /billing/addons/revoke   Admin revoke

warden/billing/gateway.py         PaymentGateway abstraction (Stripe primary, Cryptomus fallback)
warden/billing/evidence.py        ship_payment_event() → MinIO evidence/payments/
warden/workers/dunning.py         ARQ: retry failed payments (exponential back-off)
```

### Idempotency pattern

```python
key = sha256(f"{tenant_id}:{plan_id}:{timestamp // 3600}".encode()).hexdigest()
gateway.charge(amount, currency, idempotency_key=key)
```

### Key milestones

| Milestone | Acceptance Criteria |
|-----------|---------------------|
| Checkout flow | User selects Pro → Stripe Checkout → payment → plan activated in <30s |
| Webhook idempotency | Duplicate webhook delivery does not double-bill (idempotency_key test) |
| Audit trail | Every payment event in MinIO `evidence/payments/` within 5s of webhook |
| Dunning | Failed payment retried at 1h, 6h, 24h with email notification |
| Refund | Admin POST /billing/refund → Stripe refund + MinIO record |

---

## Cross-cutting: Agent Modernisation (Parallel, per 10-point plan)

Run alongside Phases 1–5. Each item maps to one of the 10 proposed extensions.

| # | Feature | Target Phase | Files |
|---|---------|--------------|-------|
| 1 | Vision Diff — baseline vs current screenshot comparison | Phase 1 | `warden/agent/tools.py` tool #31 |
| 2 | LLM-assisted smart retry for ScenarioRunner steps | Phase 1 | `warden/testing/scenarios/runner.py` |
| 3 | Auto scenario generation from ScreencastRecorder sessions | Phase 2 | `warden/workers/scenario_gen.py` |
| 4 | OLS trend prediction in WardenHealer (bypass forecast) | Phase 2 | `warden/agent/healer.py` |
| 5 | Dynamic patrol weight scheduler (`_PatrolWeights`) | Phase 3 | `warden/agent/scheduler.py` |
| 6 | axe-core accessibility assertions in visual_assert_page | Phase 3 | `warden/tools/browser.py` |
| 7 | Troubleshooting Playback HTML report from WebM + logs | Phase 4 | `warden/xai/playback.py` |
| 8 | Mutation fuzzer for visual assert calibration | Phase 4 | `warden/testing/mutation_fuzzer.py` |
| 9 | Self-adapting WardenHealer start prompt + recipe cache | Phase 5 | `warden/agent/healer.py` |
| 10 | Multi-browser patrol (Chromium/Firefox/WebKit) | Phase 5 | `warden/agent/scheduler.py` |

---

## Delivery Summary

```
Week 1    Phase 0  Foundation & CI
Week 2-3  Phase 1  Business Community
Week 3-4  Phase 2  Cyber Security Hub
Week 4-5  Phase 3  Documentation
Week 5-6  Phase 4  Settings Integration
Week 6-7  Phase 5  Payment Plan
Week 7+   Hardening: load test (k6), pentest, SOC2 evidence review
```

Each phase ships to staging, passes visual patrol, then promotes to production.
Evidence of each production deploy stored in MinIO `evidence/deploys/<date>/`.
