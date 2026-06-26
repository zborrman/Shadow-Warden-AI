# API Conventions

Load this file when working on any FastAPI router, endpoint, or API contract.

## Router mounting pattern

All routers are mounted in `warden/main.py` with `try/except ImportError` (fail-open):
```python
try:
    from warden.api.my_module import router as my_router
    app.include_router(my_router, prefix="/my-module")
except ImportError:
    pass
```

Never mount a router unconditionally — optional dependencies (playwright, liboqs, asyncpg) may not be installed.

## Endpoint naming

- Resources: plural nouns (`/listings`, `/agents`, `/negotiations`)
- Actions on resources: `POST /listings/{id}/sponsor`, `POST /agents/{id}/rotate-key`
- Well-known paths: `GET /.well-known/agent.json` (ADP), `GET /health`
- Avoid verbs in URLs except for action sub-resources

## Response conventions

- `200` — success with body
- `201` — created (POST that creates a resource)
- `400` — client error (bad payload, business rule violation)
- `402` — payment required (add-on not purchased)
- `403` — forbidden (tier too low, or X-Admin-Key missing)
- `404` — not found
- `422` — validation error (Pydantic or explicit check)
- `500` — server error (always include `detail` string)

## Auth gates

Tier gates use `require_feature()` from `warden/billing/feature_gate.py`:
```python
from warden.billing.feature_gate import require_feature
@router.post("/endpoint", dependencies=[Depends(require_feature("my_feature"))])
```

Add-on gates use `require_addon_or_feature()` from `warden/billing/addons.py`:
- HTTP 403 = tier below `min_tier`
- HTTP 402 = eligible tier but add-on not purchased

Admin-only endpoints require `X-Admin-Key` header matching `ADMIN_KEY` env var.

## M2M marketplace endpoints (frozen)

These 6 endpoints must never change signatures (agents depend on them):
```
POST /marketplace/register
GET  /marketplace/protocol
GET  /marketplace/protocol/schema/{action}
POST /marketplace/action
POST /marketplace/clear
POST /marketplace/analytics/query
```

The `POST /marketplace/action` dispatcher accepts `action_type` field. Adding new action types is backward-compatible; removing or renaming existing ones is not.

## Pagination

- `limit` query param, max 50–100 (set per endpoint)
- `offset` or `cursor` for large datasets
- Always include `total` in paginated responses

## Background tasks

Use `BackgroundTasks` for non-blocking I/O (logging, S3 uploads, Slack alerts):
```python
async def endpoint(background_tasks: BackgroundTasks):
    background_tasks.add_task(event_logger.append, entry)
```
Never block the response path with file I/O or network calls.

## GDPR

Content fields in `FilterRequest` (the `content` field) must never appear in:
- Log entries (`data/logs.json`)
- Prometheus labels
- OTel span attributes
- Error messages returned to clients
Only metadata is safe: `content_type`, `content_length`, `processing_ms`, `verdict`.
