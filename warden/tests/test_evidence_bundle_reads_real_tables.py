"""
warden/tests/test_evidence_bundle_reads_real_tables.py

The SOC 2 evidence ZIP is a customer-facing deliverable, and two of its five
sections were empty in every pack ever generated:

    _collect_training     SELECT record_json FROM training_records
    _collect_vendor_dpa   SELECT vendor_json FROM vendor_records

Neither table nor column exists. The stores are `ai_training_completions`
(`communities/training_records.py`) and `ai_vendors` + `vendor_dpa_records`
(`vendor_gov/registry.py`). SQLite raised on both, and both `except` clauses
returned `[]` — so `training_records.json` and `vendor_dpa_report.json` shipped
as empty arrays that look exactly like "this tenant has no training and no
vendors".

These tests write through the **real writers** and read through the collectors,
so a fixture cannot agree with the bug the way six of them did earlier in this
work.
"""
from __future__ import annotations

import os

os.environ.setdefault("REDIS_URL", "memory://")
os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
# VAULT_MASTER_KEY (training attestation HMAC) comes from conftest, which
# runs before this module is imported. A literal key here is both
# redundant and a gitleaks `generic-api-key` finding — the CI secret gate
# cannot tell a throwaway test key from a live one, and should not have to.


def test_training_section_is_populated_from_the_real_store(tmp_path, monkeypatch):
    from warden.communities import training_records as tr

    db = str(tmp_path / "training.db")
    prog = tr.create_program(
        community_id="comm-1", title="AI Acceptable Use", db_path=db,
    )
    tr.record_completion(
        program_id=prog.program_id, community_id="comm-1",
        employee_id="emp-7", score=0.95, db_path=db,
    )

    rows = tr.list_completions("comm-1", db_path=db)
    assert len(rows) == 1
    assert rows[0]["employee_id"] == "emp-7"
    assert rows[0]["attestation"], "the HMAC attestation must survive the read"

    from warden.compliance import evidence_bundle as eb

    monkeypatch.setattr(eb, "_TRAINING_DB_PATH", db)
    out = eb._collect_training("comm-1")
    assert len(out) == 1 and out[0]["employee_id"] == "emp-7"


def test_training_section_is_empty_only_when_it_really_is(tmp_path, monkeypatch):
    from warden.communities import training_records as tr
    from warden.compliance import evidence_bundle as eb

    db = str(tmp_path / "training_empty.db")
    tr.create_program(community_id="comm-2", title="Nobody took it", db_path=db)
    monkeypatch.setattr(eb, "_TRAINING_DB_PATH", db)
    assert eb._collect_training("comm-2") == []


def test_vendor_section_carries_vendors_and_their_dpas(tmp_path, monkeypatch):
    from warden.vendor_gov import registry as reg

    db = str(tmp_path / "vendor.db")
    v = reg.register_vendor(
        tenant_id="t-1", display_name="Anthropic", db_path=db,
    )
    reg.add_dpa(
        vendor_id=v.vendor_id, tenant_id="t-1",
        signed_at="2026-01-01", expires_at="2027-01-01", db_path=db,
    )

    report = reg.vendor_dpa_report("t-1", db_path=db)
    assert len(report) == 1
    assert report[0]["display_name"] == "Anthropic"
    assert len(report[0]["dpa_records"]) == 1, "a vendor with no DPA is the finding"

    from warden.compliance import evidence_bundle as eb

    monkeypatch.setattr(eb, "_VENDOR_DB_PATH", db)
    out = eb._collect_vendor_dpa("t-1")
    assert len(out) == 1 and out[0]["dpa_records"]


def test_vendor_section_does_not_leak_another_tenant(tmp_path, monkeypatch):
    """The old query read `tenant_id=? OR tenant_id IS NULL`, which would have
    handed one tenant's vendor list to another had the table existed."""
    from warden.compliance import evidence_bundle as eb
    from warden.vendor_gov import registry as reg

    db = str(tmp_path / "vendor_multi.db")
    reg.register_vendor(tenant_id="t-1", display_name="Ours", db_path=db)
    reg.register_vendor(tenant_id="t-2", display_name="Theirs", db_path=db)

    monkeypatch.setattr(eb, "_VENDOR_DB_PATH", db)
    names = {v["display_name"] for v in eb._collect_vendor_dpa("t-1")}
    assert names == {"Ours"}


def test_neither_collector_names_the_table_that_does_not_exist():
    """Read the AST, not the text.

    The first version of this test grepped the source and tripped on the
    explanatory docstring that names the old query — the mirror image of a
    fixture agreeing with its bug. Only executable SQL counts.
    """
    import ast
    import inspect

    from warden.compliance import evidence_bundle as eb

    sql = [
        node.value
        for node in ast.walk(ast.parse(inspect.getsource(eb)))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.lstrip().upper().startswith(("SELECT", "INSERT", "UPDATE", "DELETE"))
    ]
    for stmt in sql:
        for ghost in ("training_records", "vendor_records"):
            assert f"FROM {ghost}" not in stmt, f"evidence_bundle queries {ghost} again"
