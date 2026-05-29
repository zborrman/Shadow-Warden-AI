"""
warden/analytics/pages/15_Semantic_Layer.py  (FE-42)
Streamlit — Headless BI Semantic Layer
Tabs: Model Editor | Query Builder | AI Query | Usage Analytics
"""
from __future__ import annotations

import json
import os

import streamlit as st

st.set_page_config(page_title="Semantic Layer", page_icon="🧠", layout="wide")

TENANT = os.getenv("DEFAULT_TENANT_ID", "default")


def _engine():
    from warden.semantic_layer.engine import SemanticQueryEngine
    return SemanticQueryEngine()


def _repo():
    return None  # imported inline below


tab_editor, tab_query, tab_ai, tab_usage = st.tabs(
    ["Model Editor", "Query Builder", "AI Query", "Usage Analytics"]
)

# ── Model Editor ──────────────────────────────────────────────────────────────
with tab_editor:
    st.subheader("Semantic Model Editor")
    st.caption("Define metrics, dimensions and joins as a deterministic contract")

    col_list, col_form = st.columns([1, 2])

    with col_list:
        st.markdown("**Existing Models**")
        try:
            from warden.semantic_layer.repository import list_models
            models = list_models(TENANT)
            if models:
                selected = st.selectbox("Select model", [m.name for m in models])
                sel_model = next((m for m in models if m.name == selected), None)
                if sel_model:
                    st.json(sel_model.to_dict(), expanded=False)
            else:
                st.info("No models yet.")
        except Exception as e:
            st.error(str(e))

    with col_form:
        st.markdown("**Create New Model**")
        with st.form("new_model"):
            name         = st.text_input("Model name", placeholder="security_events")
            source_table = st.text_input("Source table", placeholder="events")
            description  = st.text_area("Description", height=60)
            metrics_json = st.text_area("Metrics (JSON)", height=120,
                value='[{"name":"total","sql_expression":"COUNT(*)","description":"Total requests"}]')
            dims_json    = st.text_area("Dimensions (JSON)", height=80,
                value='[{"name":"tenant","sql_field":"tenant_id","type":"string"}]')
            submit = st.form_submit_button("Create Model", type="primary")

            if submit and name and source_table:
                try:
                    from warden.semantic_layer.models import Dimension, Metric, SemanticModel
                    from warden.semantic_layer.repository import create_model
                    metrics    = [Metric(**m) for m in json.loads(metrics_json)]
                    dimensions = [Dimension(**d) for d in json.loads(dims_json)]
                    model = SemanticModel(
                        name=name, description=description, owner_tenant=TENANT,
                        source_table=source_table, metrics=metrics, dimensions=dimensions,
                    )
                    ok, errors = _engine().validate_model(model)
                    if not ok:
                        st.error("Validation: " + "; ".join(errors))
                    else:
                        created = create_model(model)
                        st.success(f"Created: {created.id}")
                        st.rerun()
                except Exception as e:
                    st.error(str(e))

# ── Query Builder ─────────────────────────────────────────────────────────────
with tab_query:
    st.subheader("Query Builder")
    st.caption("Deterministic metric calculation — no LLM in the query path")

    try:
        from warden.semantic_layer.repository import list_models
        models = list_models(TENANT)
        if not models:
            st.info("Create a model first.")
        else:
            import pandas as pd
            model_name = st.selectbox("Model", [m.name for m in models], key="qb_model")
            model = next((m for m in models if m.name == model_name), None)
            if model:
                col_m, col_d = st.columns(2)
                with col_m:
                    sel_metrics = st.multiselect("Metrics", model.metric_names(),
                                                  default=model.metric_names()[:1])
                with col_d:
                    sel_dims    = st.multiselect("Dimensions", model.dimension_names())
                limit = st.slider("Limit", 10, 1000, 100)

                if st.button("Run Query", type="primary"):
                    from warden.semantic_layer.models import QueryObject
                    q      = QueryObject(model_id=model.id, metrics=sel_metrics,
                                         dimensions=sel_dims, limit=limit)
                    result = _engine().execute_query(q, model)
                    st.code(result.sql, language="sql")
                    if result.rows:
                        st.dataframe(pd.DataFrame(result.rows), use_container_width=True)
                        st.caption(f"{result.row_count} rows · {result.execution_ms:.1f} ms")
                    else:
                        st.info("No rows returned.")
    except Exception as e:
        st.error(str(e))

# ── AI Query ──────────────────────────────────────────────────────────────────
with tab_ai:
    st.subheader("AI Natural Language Query")
    st.caption("SOVA converts your question to a QueryObject — SQL is generated by the engine, not the LLM")

    try:
        from warden.semantic_layer.repository import list_models
        models = list_models(TENANT)
        if not models:
            st.info("Create a model first.")
        else:
            model_name = st.selectbox("Model", [m.name for m in models], key="ai_model")
            model = next((m for m in models if m.name == model_name), None)
            question = st.text_area("Your question", placeholder="Show me total events by tenant for the last 7 days")

            if st.button("Ask AI", type="primary") and question and model:
                with st.spinner("SOVA is generating QueryObject..."):
                    try:
                        import anthropic
                        ctx = _engine().get_context_for_llm(model)
                        prompt = (
                            f"Given this semantic model:\n{json.dumps(ctx, indent=2)}\n\n"
                            f"Convert this question to a QueryObject JSON:\n{question}\n\n"
                            "Return ONLY a valid JSON object with fields: "
                            "model_id, metrics (list of names), dimensions (list of names), "
                            "filters (list of {dimension, operator, value}), limit (int)."
                        )
                        client = anthropic.Anthropic()
                        msg = client.messages.create(
                            model="claude-haiku-4-5-20251001",
                            max_tokens=512,
                            messages=[{"role": "user", "content": prompt}],
                        )
                        raw = msg.content[0].text.strip()
                        if raw.startswith("```"):
                            raw = raw.split("```")[1].lstrip("json").strip()
                        query_data = json.loads(raw)
                        query_data["model_id"] = model.id

                        from warden.semantic_layer.models import Filter, QueryObject
                        q = QueryObject(
                            model_id=model.id,
                            metrics=query_data.get("metrics", []),
                            dimensions=query_data.get("dimensions", []),
                            filters=[Filter(**f) for f in query_data.get("filters", [])],
                            limit=query_data.get("limit", 100),
                        )
                        result = _engine().execute_query(q, model)

                        st.markdown("**Generated QueryObject:**")
                        st.json(query_data, expanded=False)
                        st.markdown("**SQL (generated by engine, not LLM):**")
                        st.code(result.sql, language="sql")
                        if result.rows:
                            import pandas as pd
                            st.dataframe(pd.DataFrame(result.rows), use_container_width=True)
                        else:
                            st.info("No rows returned.")
                    except ImportError:
                        st.warning("Anthropic API key not configured — AI Query unavailable.")
                    except Exception as e:
                        st.error(f"AI Query failed: {e}")
    except Exception as e:
        st.error(str(e))

# ── Usage Analytics ───────────────────────────────────────────────────────────
with tab_usage:
    st.subheader("Query Usage Analytics")
    try:
        from warden.semantic_layer.repository import query_usage_stats
        import pandas as pd
        stats = query_usage_stats(TENANT, limit=50)
        if stats:
            df = pd.DataFrame(stats)
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Queries", len(df))
            col2.metric("Avg Exec Time", f"{df['exec_ms'].mean():.1f} ms")
            col3.metric("Total Rows", int(df['row_count'].sum()))
            st.dataframe(df[["model_id", "metrics", "dimensions", "exec_ms",
                              "row_count", "created_at"]],
                         use_container_width=True, hide_index=True)
        else:
            st.info("No queries executed yet.")
    except Exception as e:
        st.error(str(e))
