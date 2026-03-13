# Shadow Warden AI — Developer Makefile
# Usage: make <target>
# Run `make help` for a full list of targets.

.PHONY: help up down build logs test test-fast test-cov lint fmt typecheck \
        k6-smoke k6-load sdk-test clean

PYTHON     ?= python
PYTEST     ?= pytest
RUFF       ?= ruff
MYPY       ?= mypy
DOCKER     ?= docker
COMPOSE    ?= docker compose
K6         ?= k6

WARDEN_URL ?= http://localhost:8001

# ── Help ──────────────────────────────────────────────────────────────────────

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ── Docker ────────────────────────────────────────────────────────────────────

up:  ## Start all services (production mode)
	$(COMPOSE) up --build -d
	@echo "Gateway:   $(WARDEN_URL)"
	@echo "Dashboard: http://localhost:8501"
	@echo "Grafana:   http://localhost:3000"

up-dev:  ## Start services in development mode (hot-reload)
	$(COMPOSE) -f docker-compose.yml -f docker-compose.dev.yml up --build

down:  ## Stop all services
	$(COMPOSE) down

build:  ## Build Docker images without starting
	$(COMPOSE) build

logs:  ## Follow logs for warden service
	$(COMPOSE) logs -f warden

logs-all:  ## Follow logs for all services
	$(COMPOSE) logs -f

# ── Tests ─────────────────────────────────────────────────────────────────────

test:  ## Run unit + integration tests (excludes adversarial + slow)
	$(PYTEST) warden/tests/ -v --tb=short -m "not adversarial and not slow"

test-fast:  ## Run only unit tests (no ML model load)
	$(PYTEST) warden/tests/ -v --tb=short -m "not adversarial and not slow and not integration"

test-cov:  ## Run full suite with coverage gate (≥75%)
	$(PYTEST) warden/tests/ --tb=short -m "not adversarial" \
		--cov=warden --cov-fail-under=75 -q

test-adversarial:  ## Run adversarial corpus tests (informational — don't block on failure)
	$(PYTEST) warden/tests/ -v --tb=short -m "adversarial" || true

sdk-test:  ## Run Python SDK tests
	$(PYTEST) sdk/python/tests/ -v --tb=short

# ── Linting ───────────────────────────────────────────────────────────────────

lint:  ## Run ruff + mypy
	$(RUFF) check warden/ analytics/ --ignore E501
	$(MYPY) warden/ --ignore-missing-imports --no-strict-optional

fmt:  ## Auto-fix ruff lint issues and format code
	$(RUFF) check warden/ analytics/ --fix
	$(RUFF) format warden/ analytics/

typecheck:  ## Run mypy only
	$(MYPY) warden/ --ignore-missing-imports --no-strict-optional

# ── k6 Load Tests ─────────────────────────────────────────────────────────────

k6-smoke:  ## Run k6 smoke test (1 VU × 30 s) against running gateway
	$(K6) run k6/smoke_test.js --env BASE_URL=$(WARDEN_URL)

k6-baseline:  ## Run k6 baseline scenario (5 VU × 60 s)
	$(K6) run k6/load_test.js --env BASE_URL=$(WARDEN_URL) --env SCENARIO=baseline

k6-ramp:  ## Run k6 ramp scenario (0→50→0 VU, 8 min)
	$(K6) run k6/load_test.js --env BASE_URL=$(WARDEN_URL) --env SCENARIO=ramp

k6-spike:  ## Run k6 spike scenario (0→100→0 VU, 2 min)
	$(K6) run k6/load_test.js --env BASE_URL=$(WARDEN_URL) --env SCENARIO=spike

k6-soak:  ## Run k6 soak test (20 VU × 30 min) — long-running!
	$(K6) run k6/load_test.js --env BASE_URL=$(WARDEN_URL) --env SCENARIO=soak

k6-all:  ## Run full k6 load test suite (all scenarios)
	$(K6) run k6/load_test.js --env BASE_URL=$(WARDEN_URL)

# ── Mutation Testing ──────────────────────────────────────────────────────────

mutmut:  ## Run mutation tests (Linux/WSL/CI only)
	mutmut run --no-progress
	mutmut results

# ── Install ───────────────────────────────────────────────────────────────────

install:  ## Install project + dev dependencies locally
	pip install torch --index-url https://download.pytorch.org/whl/cpu
	pip install -e ".[dev]"
	pip install -r warden/requirements.txt

install-sdk:  ## Install Python SDK locally (editable)
	pip install -e "sdk/python[dev]"

install-saml:  ## Install SAML 2.0 dependencies (python3-saml + PyJWT)
	pip install python3-saml PyJWT

install-hooks:  ## Install pre-commit hooks
	pre-commit install

# ── Health ────────────────────────────────────────────────────────────────────

health:  ## Check gateway health
	curl -sf $(WARDEN_URL)/health | python -m json.tool

filter-test:  ## Send a test filter request
	curl -sf -X POST $(WARDEN_URL)/filter \
		-H "Content-Type: application/json" \
		-d '{"content": "What is the capital of France?", "tenant_id": "dev"}' \
		| python -m json.tool

# ── Clean ─────────────────────────────────────────────────────────────────────

clean:  ## Remove Python cache, test artefacts, and tmp files
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	rm -f /tmp/warden_test*.json /tmp/warden_test_*.json
