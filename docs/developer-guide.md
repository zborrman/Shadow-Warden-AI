# Shadow Warden AI — Developer Guide

**Audience:** Contributors, developers extending the platform
**Prerequisites:** Python 3.11+, Docker, Node.js 20+, Git

---

## 1. Repository structure

```
shadow-warden-ai/
├── warden/                  # FastAPI backend (Python 3.12)
│   ├── main.py              # App factory, router mounts, lifespan
│   ├── topology_guard.py    # TDA Gatekeeper
│   ├── brain/               # HyperbolicBrain, EvolutionEngine
│   ├── causal_arbiter.py    # Bayesian DAG
│   ├── agent/               # SOVA, MasterAgent, WardenHealer
│   ├── marketplace/         # M2M Marketplace
│   ├── communities/         # SEP, peering, charter, behavioral
│   ├── compliance/          # CompliancePostureService
│   ├── semantic_layer/      # Headless BI
│   ├── document_intel/      # MarkItDown converter
│   ├── sovereign/           # Jurisdictions, MASQUE tunnels
│   ├── billing/             # Tier limits, add-ons, feature gates
│   ├── api/                 # FastAPI routers
│   ├── analytics/           # Streamlit pages
│   └── tests/               # pytest test files
├── dashboard/               # Next.js 14 SOC Dashboard
├── portal/                  # Next.js 14 Customer Portal
├── site/                    # Astro 4 marketing site
├── sdks/node/               # @shadow-warden/sdk (TypeScript)
├── obsidian-plugin/         # TypeScript Obsidian plugin
├── grafana/                 # Grafana dashboards + alert rules
├── docker/                  # Caddy config
├── scripts/                 # CLI tools (impact analysis, GitHub scan)
├── docs/                    # This documentation
├── openapi.json             # OpenAPI 3.0.3 spec
├── docker-compose.yml       # Full orchestration
└── ROADMAP.md               # Feature registry
```

---

## 2. Local development setup

### 2.1 Clone and configure

```bash
git clone https://github.com/shadow-warden-ai/shadow-warden-ai.git
cd shadow-warden-ai
cp .env.example .env
```

Edit `.env` — minimum required vars:

```env
WARDEN_API_KEY=dev-local-key-change-me
VAULT_MASTER_KEY=<32-byte Fernet key — generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())">
ALLOW_UNAUTHENTICATED=false
ANTHROPIC_API_KEY=          # leave empty to disable EvolutionEngine (still works)
REDIS_URL=redis://redis:6379
LOGS_PATH=/tmp/warden_logs.json
```

### 2.2 Start with Docker Compose (recommended)

```bash
docker compose up --build
```

Services start on:
- `warden` API: `http://localhost:8001`
- `portal`: `http://localhost:3001`
- `dashboard`: `http://localhost:3002`
- `analytics` (Streamlit): `http://localhost:8501`
- `grafana`: `http://localhost:3000`
- `prometheus`: `http://localhost:9090`
- `minio` console: `http://localhost:9001`

<!-- SCREENSHOT: docker compose ps output showing all 11 services healthy -->
<!-- TODO: capture and save as docs/images/docker-compose-ps.png -->
<!-- Figure 6: docker compose ps — all 11 services (proxy, warden, app, analytics, dashboard, postgres, redis, prometheus, grafana, minio, minio-init) showing "Up" status with port bindings -->

### 2.3 Run tests locally (without Docker)

```bash
# CPU-only torch (required — GPU torch breaks CI)
pip install torch --index-url https://download.pytorch.org/whl/cpu

# Install dependencies
pip install -e ".[dev]"
pip install -r warden/requirements.txt

# Run test suite (skip adversarial + slow markers)
pytest warden/tests/ -v --tb=short -m "not adversarial and not slow"

# Coverage gate (must pass before merge)
pytest warden/tests/ --tb=short -m "not adversarial" --cov=warden --cov-fail-under=75
```

### 2.4 Lint

```bash
ruff check warden/ analytics/ --ignore E501
mypy warden/ --ignore-missing-imports --no-strict-optional
```

### 2.5 Frontend development

```bash
# SOC Dashboard
cd dashboard && npm install && npm run dev    # → http://localhost:3002

# Portal
cd portal && npm install && npm run dev       # → http://localhost:3001

# Marketing site
cd site && npm install && npm run dev         # → http://localhost:4321
```

---

## 3. Adding a new backend module

Follow this pattern (example: adding a new `risk_scoring` module):

### Step 1: Business logic

```
warden/risk_scoring/__init__.py   # empty
warden/risk_scoring/service.py    # pure Python, SQLite or Redis, no HTTP calls
```

```python
# warden/risk_scoring/service.py
import os, sqlite3
from dataclasses import dataclass

DB_PATH = os.getenv("RISK_SCORING_DB_PATH", "/tmp/warden_risk.db")

@dataclass
class RiskEntry:
    entry_id: str
    tenant_id: str
    score: float
    ...

def _db() -> sqlite3.Connection:
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""CREATE TABLE IF NOT EXISTS risk_entries (
        entry_id TEXT PRIMARY KEY, tenant_id TEXT, score REAL, ...
    )""")
    return con

def add_entry(tenant_id: str, score: float) -> RiskEntry: ...
def list_entries(tenant_id: str) -> list[RiskEntry]: ...
```

### Step 2: FastAPI router

```
warden/api/risk_scoring.py
```

```python
# warden/api/risk_scoring.py
from fastapi import APIRouter, Depends
from warden.billing.feature_gate import require_feature
from warden.risk_scoring.service import add_entry, list_entries

router = APIRouter(prefix="/risk-scoring", tags=["Risk Scoring"])
_GATE = [Depends(require_feature("risk_scoring_enabled"))]

@router.get("/entries", dependencies=_GATE)
async def get_entries(tenant_id: str = "default") -> list[dict]:
    return [vars(e) for e in list_entries(tenant_id)]

@router.post("/entries", dependencies=_GATE, status_code=201)
async def create_entry(tenant_id: str, score: float) -> dict:
    return vars(add_entry(tenant_id, score))
```

### Step 3: Mount router in `warden/main.py`

```python
try:
    from warden.api.risk_scoring import router as _risk_router
    app.include_router(_risk_router)
    log.info("Risk Scoring mounted at /risk-scoring")
except ImportError:
    log.warning("risk_scoring router not available — /risk-scoring skipped.")
```

### Step 4: Feature gate

In `warden/billing/feature_gate.py`, add to `TIER_LIMITS`:

```python
"risk_scoring_enabled": {
    "starter": False, "individual": True, "community_business": True,
    "pro": True, "enterprise": True,
},
```

### Step 5: Tests

```
warden/tests/test_risk_scoring.py
```

```python
import os, uuid
os.environ.setdefault("RISK_SCORING_DB_PATH", "/tmp/test_risk.db")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("REDIS_URL", "memory://")

from fastapi.testclient import TestClient
from warden.main import app

client = TestClient(app)

def _tid(): return f"tenant-{uuid.uuid4().hex[:8]}"

class TestRiskScoringAPI:
    def test_create_returns_201(self):
        r = client.post("/risk-scoring/entries", params={"tenant_id": _tid(), "score": 0.75})
        assert r.status_code == 201

    def test_list_returns_entries(self):
        tid = _tid()
        client.post("/risk-scoring/entries", params={"tenant_id": tid, "score": 0.5})
        r = client.get("/risk-scoring/entries", params={"tenant_id": tid})
        assert len(r.json()) == 1
```

Run: `pytest warden/tests/test_risk_scoring.py -v --tb=short`

---

## 4. Adding a SOVA tool

SOVA tools live in `warden/agent/tools.py`. Each tool is:
1. An `async def fn(**kwargs) -> dict` function.
2. An Anthropic schema entry in the `TOOLS` list.
3. An entry in the `TOOL_HANDLERS` dispatch table.

```python
# In warden/agent/tools.py

async def score_risk(tenant_id: str = "default", **_) -> dict:
    """Tool #56 — Get current risk score summary for a tenant."""
    try:
        import httpx
        r = await httpx.AsyncClient().get(
            f"http://localhost:8001/risk-scoring/entries",
            params={"tenant_id": tenant_id},
            headers={"X-API-Key": os.getenv("WARDEN_API_KEY", "")},
            timeout=5,
        )
        return r.json()
    except Exception as exc:
        return {"error": str(exc)}

# Add to TOOLS list:
{
    "name": "score_risk",
    "description": "Get the risk score summary for a tenant.",
    "input_schema": {
        "type": "object",
        "properties": {
            "tenant_id": {"type": "string", "description": "Tenant ID"}
        },
    },
},

# Add to TOOL_HANDLERS:
"score_risk": score_risk,
```

---

## 5. Code style

| Rule | Detail |
|---|---|
| Line length | 100 chars (ruff `line-length=100`) |
| Ruff rules | `E,F,W,I,N,UP,B,C4,SIM`; ignore `E501,B008` |
| Type annotations | Not required on unchanged code; use on new public functions |
| Comments | Only for non-obvious WHY (not WHAT) |
| Docstrings | Not required; one short line max |
| Python features | 3.11+ (`match/case`, `X | Y` unions) |
| Test isolation | UUID-based tenant/community IDs — never reuse between tests |
| Markers | `@pytest.mark.adversarial`, `@pytest.mark.slow`, `@pytest.mark.integration` |

---

## 6. CI pipeline

Three GitHub Actions jobs on every push/PR to `main` / `develop`:

| Job | What runs |
|---|---|
| `test` | pytest matrix (3.11 + 3.12), coverage gate ≥75% |
| `lint` | ruff + mypy |
| `docker-build` | Phase 1 (import test) + Phase 2 (runtime /health check) |

Mutation testing (`mutmut`) runs on `secret_redactor.py` + `semantic_guard.py`.
Threshold: ≤20 surviving mutants.

GitHub Actions CI security gate (`warden-scan.yml`) scans every commit diff for
policy violations and posts a PR comment with a verdict table.

---

## 7. PR process

1. Branch from `main`: `git checkout -b feat/your-feature`.
2. Run lint + tests locally.
3. Open PR — CI runs automatically.
4. Coverage gate must pass (`--cov-fail-under=75`).
5. Get one review approval.
6. Squash-merge.

Version bump follows semantic versioning. Patch versions ship weekly.
