"""
warden/tests/test_semantic_layer.py  (FE-42)
Semantic Layer — 12 tests covering models, engine, repository, OSI.
"""
from __future__ import annotations

import os
import pytest

os.environ.setdefault("SEMANTIC_DB_PATH", "/tmp/test_semantic.db")


def _make_model(name: str = "test_model", tenant: str = "t1"):
    from warden.semantic_layer.models import Dimension, Metric, SemanticModel
    return SemanticModel(
        name=name,
        description="Test model",
        owner_tenant=tenant,
        source_table="events",
        metrics=[
            Metric(name="total_events", sql_expression="COUNT(*)", description="Total events"),
            Metric(name="blocked_count", sql_expression="SUM(CASE WHEN blocked=1 THEN 1 ELSE 0 END)",
                   description="Blocked requests"),
        ],
        dimensions=[
            Dimension(name="tenant", sql_field="tenant_id", type="string"),
            Dimension(name="day",    sql_field="DATE(created_at)", type="time"),
        ],
    )


class TestSemanticModels:
    def test_model_metric_names(self):
        m = _make_model()
        assert "total_events" in m.metric_names()
        assert "blocked_count" in m.metric_names()

    def test_model_dimension_names(self):
        m = _make_model()
        assert "tenant" in m.dimension_names()
        assert "day" in m.dimension_names()

    def test_model_to_dict(self):
        m = _make_model()
        d = m.to_dict()
        assert d["name"] == "test_model"
        assert len(d["metrics"]) == 2


class TestSemanticRepository:
    @pytest.fixture(autouse=True)
    def _clean(self, tmp_path):
        db = str(tmp_path / "sem.db")
        os.environ["SEMANTIC_DB_PATH"] = db
        yield
        if os.path.exists(db):
            os.remove(db)

    def test_create_and_get(self):
        from warden.semantic_layer.repository import create_model, get_model
        model = _make_model()
        created = create_model(model)
        assert created.id
        retrieved = get_model(created.id, "t1")
        assert retrieved is not None
        assert retrieved.name == "test_model"

    def test_list_models(self):
        from warden.semantic_layer.repository import create_model, list_models
        create_model(_make_model("model_a"))
        create_model(_make_model("model_b"))
        models = list_models("t1")
        assert len(models) == 2

    def test_update_model(self):
        from warden.semantic_layer.repository import create_model, get_model, update_model
        m = create_model(_make_model())
        m.description = "Updated"
        update_model(m)
        updated = get_model(m.id, "t1")
        assert updated.description == "Updated"

    def test_delete_model(self):
        from warden.semantic_layer.repository import create_model, delete_model, get_model
        m = create_model(_make_model("model_del"))
        ok = delete_model(m.id, "t1")
        assert ok is True
        assert get_model(m.id, "t1") is None

    def test_delete_nonexistent(self):
        from warden.semantic_layer.repository import delete_model
        assert delete_model("nonexistent", "t1") is False


class TestSemanticEngine:
    def _engine(self):
        from warden.semantic_layer.engine import SemanticQueryEngine
        return SemanticQueryEngine()

    def test_compile_query_select_metrics(self):
        from warden.semantic_layer.models import QueryObject
        model = _make_model()
        q = QueryObject(model_id="x", metrics=["total_events"])
        sql = self._engine().compile_query(q, model)
        assert "COUNT(*)" in sql
        assert "FROM events" in sql

    def test_compile_query_with_dimension(self):
        from warden.semantic_layer.models import QueryObject
        model = _make_model()
        q = QueryObject(model_id="x", metrics=["total_events"], dimensions=["tenant"])
        sql = self._engine().compile_query(q, model)
        assert "tenant_id" in sql
        assert "GROUP BY" in sql

    def test_compile_query_with_filter(self):
        from warden.semantic_layer.models import Filter, QueryObject
        model = _make_model()
        q = QueryObject(
            model_id="x", metrics=["total_events"],
            filters=[Filter(dimension="tenant", operator="eq", value="acme")],
        )
        sql = self._engine().compile_query(q, model)
        assert "WHERE" in sql
        assert "acme" in sql

    def test_validate_model_valid(self):
        ok, errors = self._engine().validate_model(_make_model())
        assert ok is True
        assert errors == []

    def test_llm_context_structure(self):
        model = _make_model()
        model.id = "test-id"
        ctx = self._engine().get_context_for_llm(model)
        assert ctx["model_id"] == "test-id"
        assert len(ctx["metrics"]) == 2
        assert "sql_expression" not in str(ctx)  # SQL never exposed to LLM

    def test_osi_roundtrip(self):
        engine = self._engine()
        model  = _make_model()
        model.id = "osi-test"
        exported = engine.export_osi(model)
        assert exported["osi_version"] == "1.0"
        imported = engine.import_osi(exported, "t1")
        assert imported.name == model.name
        assert len(imported.metrics) == len(model.metrics)
