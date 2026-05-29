"""
Streamlit page: Semantic Layer (Headless BI) — FE-42

Tabs
────
  Models      — registered semantic models + their metrics/dimensions
  Query       — interactive QueryObject builder → live SQL preview
  AI Query    — natural-language intent → SQL (Pro+, requires ANTHROPIC_API_KEY)
  Docs        — architecture overview
"""
from __future__ import annotations

import os
import time

import requests
import streamlit as st

st.set_page_config(page_title="Semantic Layer", page_icon="🗃️", layout="wide")

_BASE     = os.getenv("WARDEN_INTERNAL_URL", "http://localhost:8001")
_API_KEY  = os.getenv("WARDEN_API_KEY", "")
_HEADERS  = {"X-API-Key": _API_KEY} if _API_KEY else {}

# ── CSS ───────────────────────────────────────────────────────────────────────

st.markdown("""
<style>
.metric-chip {
    display:inline-block; background:#1e293b; color:#7dd3fc;
    border-radius:6px; padding:2px 8px; font-size:0.75rem;
    margin:2px; font-family:monospace;
}
.dim-chip {
    display:inline-block; background:#1e293b; color:#86efac;
    border-radius:6px; padding:2px 8px; font-size:0.75rem;
    margin:2px; font-family:monospace;
}
.sql-block {
    background:#0f172a; color:#e2e8f0; border-radius:8px;
    padding:16px; font-family:monospace; font-size:0.85rem;
    white-space:pre; overflow-x:auto;
}
.shipped-badge {
    display:inline-block; background:#16a34a22; color:#4ade80;
    border:1px solid #4ade8040; border-radius:12px;
    padding:2px 10px; font-size:0.75rem; font-weight:600;
}
</style>
""", unsafe_allow_html=True)

st.title("🗃️ Semantic Layer (Headless BI)")
st.markdown(
    '<span class="shipped-badge">✅ Shipped · v5.1 · Pro+</span>',
    unsafe_allow_html=True,
)
st.caption(
    "Centralized semantic contract for metrics, dimensions, and access rules. "
    "LLM translates natural-language intent to a QueryObject; "
    "the engine generates deterministic SQL."
)

# ── Helpers ───────────────────────────────────────────────────────────────────

@st.cache_data(ttl=30)
def _load_models() -> list[dict]:
    try:
        r = requests.get(f"{_BASE}/semantic-layer/models", headers=_HEADERS, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as exc:
        st.warning(f"Could not reach warden API: {exc}")
        return []


@st.cache_data(ttl=60)
def _load_model_detail(model_id: str) -> dict:
    try:
        r = requests.get(f"{_BASE}/semantic-layer/models/{model_id}", headers=_HEADERS, timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception:
        return {}


# ── Tabs ──────────────────────────────────────────────────────────────────────

tab_models, tab_query, tab_ai, tab_docs = st.tabs(
    ["📋 Models", "🔍 Query Builder", "🤖 AI Query", "📖 Docs"]
)

# ── Tab: Models ───────────────────────────────────────────────────────────────
with tab_models:
    models = _load_models()
    if not models:
        st.info("No models loaded — ensure warden API is running.")
    else:
        st.subheader(f"{len(models)} Semantic Models")
        for m in models:
            with st.expander(f"**{m['name']}** — `{m['id']}`"):
                st.caption(m.get("description", ""))
                detail = _load_model_detail(m["id"])
                c1, c2 = st.columns(2)
                with c1:
                    st.markdown("**Metrics**")
                    for met in detail.get("metrics", []):
                        st.markdown(
                            f'<span class="metric-chip">{met["name"]}</span>'
                            f' <small style="color:#94a3b8">{met.get("description","")}</small>',
                            unsafe_allow_html=True,
                        )
                with c2:
                    st.markdown("**Dimensions**")
                    for dim in detail.get("dimensions", []):
                        st.markdown(
                            f'<span class="dim-chip">{dim["name"]}</span>'
                            f' <small style="color:#94a3b8">{dim.get("description","")}</small>',
                            unsafe_allow_html=True,
                        )

# ── Tab: Query Builder ────────────────────────────────────────────────────────
with tab_query:
    models_list = _load_models()
    if not models_list:
        st.info("Load models first.")
    else:
        model_ids = [m["id"] for m in models_list]
        sel_id = st.selectbox("Semantic model", model_ids, key="qb_model")
        detail = _load_model_detail(sel_id) if sel_id else {}

        metric_names = [m["name"] for m in detail.get("metrics", [])]
        dim_names    = [d["name"] for d in detail.get("dimensions", [])]

        sel_metrics = st.multiselect("Metrics", metric_names, default=metric_names[:2], key="qb_metrics")
        sel_dims    = st.multiselect("Dimensions", dim_names, default=dim_names[:1] if dim_names else [], key="qb_dims")
        limit       = st.slider("Row limit", 10, 5000, 1000, step=10, key="qb_limit")

        if st.button("Generate SQL", key="qb_run"):
            if not sel_metrics:
                st.error("Select at least one metric.")
            else:
                payload = {
                    "model_id":   sel_id,
                    "metrics":    sel_metrics,
                    "dimensions": sel_dims,
                    "filters":    [],
                    "limit":      limit,
                }
                t0 = time.perf_counter()
                try:
                    r = requests.post(
                        f"{_BASE}/semantic-layer/query",
                        json=payload,
                        headers=_HEADERS,
                        timeout=10,
                    )
                    r.raise_for_status()
                    result = r.json()
                    ms = round((time.perf_counter() - t0) * 1000, 1)
                    st.success(f"SQL generated in {result.get('generation_ms', ms)} ms")
                    st.markdown(
                        f'<div class="sql-block">{result["sql"]}</div>',
                        unsafe_allow_html=True,
                    )
                    st.caption("Copy and run against your PostgreSQL / TimescaleDB instance.")
                except Exception as exc:
                    st.error(f"Query failed: {exc}")

# ── Tab: AI Query ─────────────────────────────────────────────────────────────
with tab_ai:
    st.markdown("**Natural-language → SQL** via Claude Haiku (Pro+ tier required).")
    models_list2 = _load_models()
    if not models_list2:
        st.info("Load models first.")
    else:
        ai_model_id = st.selectbox("Model", [m["id"] for m in models_list2], key="ai_model")
        intent = st.text_area(
            "Describe what you want",
            placeholder='e.g. "Show me total blocked requests by tenant for the last 7 days"',
            height=80,
            key="ai_intent",
        )
        ai_limit = st.number_input("Limit", min_value=1, max_value=10000, value=1000, key="ai_limit")

        if st.button("Translate & Generate SQL", key="ai_run"):
            if not intent.strip():
                st.error("Enter an intent.")
            else:
                payload = {"model_id": ai_model_id, "intent": intent, "limit": int(ai_limit)}
                try:
                    r = requests.post(
                        f"{_BASE}/semantic-layer/query/intent",
                        json=payload,
                        headers=_HEADERS,
                        timeout=30,
                    )
                    if r.status_code == 503:
                        st.warning("ANTHROPIC_API_KEY not set or anthropic package missing — AI Query unavailable.")
                    elif r.status_code == 402:
                        st.warning("Pro+ plan required for AI Query.")
                    else:
                        r.raise_for_status()
                        result = r.json()
                        st.success(f"SQL generated in {result.get('generation_ms', '?')} ms")
                        st.markdown(
                            f'<div class="sql-block">{result["sql"]}</div>',
                            unsafe_allow_html=True,
                        )
                except Exception as exc:
                    st.error(f"Request failed: {exc}")

# ── Tab: Docs ─────────────────────────────────────────────────────────────────
with tab_docs:
    st.markdown("""
## Architecture

```
NL Intent
    ↓
Claude Haiku  →  QueryObject (model_id, metrics[], dimensions[], filters[])
    ↓
SemanticEngine.generate()
    ↓
Deterministic SQL  →  PostgreSQL / TimescaleDB
```

### Key concepts

| Concept | Description |
|---------|-------------|
| **SemanticModel** | Named contract: source table, metrics (aggregation expressions), dimensions (column mappings), access rules |
| **QueryObject** | Structured query: which model, which metrics, which dimensions, optional filters + row limit |
| **AccessRule** | Per-tenant allow-list of metrics/dimensions — enforced before SQL generation |
| **IntentRequest** | Raw NL text → Claude Haiku → QueryObject (Pro+ only) |

### API endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/semantic-layer/models` | List models |
| GET | `/semantic-layer/models/{id}` | Model detail |
| POST | `/semantic-layer/models` | Register custom model (Pro+) |
| POST | `/semantic-layer/query` | Generate SQL from QueryObject |
| POST | `/semantic-layer/query/intent` | NL → SQL via LLM (Pro+) |

### Built-in models

- **filter_events** — security filter decisions (total_requests, block_count, flag_count, avg_latency_ms, p99_latency_ms)
- **ers_scores** — entity risk scores (avg_score, max_score, shadow_bans)
- **billing_usage** — per-tenant billing (requests_used, cost_usd, quota_pct)
""")
