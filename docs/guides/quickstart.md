# Quick Start

## Prerequisites

- Docker ≥ 24 + Docker Compose v2
- Python 3.11+ (for local dev / tests)
- `ANTHROPIC_API_KEY` (optional — disables Evolution Engine if absent)

---

## 1. Clone and configure

```bash
git clone https://github.com/zborrman/Shadow-Warden-AI.git
cd Shadow-Warden-AI
cp .env.example .env   # fill in WARDEN_API_KEY + optional keys
```

Minimum `.env`:

```env
WARDEN_API_KEY=your-secret-key
ALLOW_UNAUTHENTICATED=false
REDIS_URL=redis://redis:6379/0
DATABASE_URL=postgresql://warden:warden@postgres:5432/warden
```

---

## 2. Start all services

```bash
docker compose up --build
```

Services start on:

| Service | Port | Purpose |
|---------|------|---------|
| Warden gateway | 8001 | Main filter API |
| Analytics dashboard | 8501 | Streamlit security dashboard |
| MinIO | 9000/9001 | S3-compatible evidence store |
| Prometheus | 9090 | Metrics |
| Grafana | 3000 | Dashboards |

---

## 3. Filter your first request

```bash
curl -X POST http://localhost:8001/filter \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"content": "Hello, how are you?", "tenant_id": "default"}'
```

Response:

```json
{
  "allowed": true,
  "risk_level": "LOW",
  "blocked": false,
  "processing_ms": 1.4,
  "stages": { "topology": "PASS", "semantic": "PASS", "brain": "PASS" }
}
```

---

## 4. Run the test suite

```bash
pip install -e ".[dev]" -r warden/requirements.txt
pytest warden/tests/ -v --tb=short -m "not adversarial and not slow"
```

---

## 5. Start the ARQ worker (optional)

Background jobs (CVE scanner, community moderation, SOVA crons):

```bash
arq warden.workers.settings.WorkerSettings
```

---

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `WARDEN_API_KEY` | — | Gateway auth key (required) |
| `ALLOW_UNAUTHENTICATED` | `false` | Skip auth (tests only) |
| `ANTHROPIC_API_KEY` | — | Enables Evolution Engine + SOVA |
| `NVIDIA_API_KEY` | — | NIM Nemotron content moderation |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis for cache + ERS |
| `SLACK_WEBHOOK_URL` | — | Alert notifications |
| `ADMIN_KEY` | — | Admin endpoints (`DELETE`, `POST /cve-scan`) |
| `CVE_REPORT_PATH` | `data/cve_report.json` | CVE scan output |
| `COMMUNITY_DB_PATH` | `/tmp/warden_community.db` | Community SQLite |
