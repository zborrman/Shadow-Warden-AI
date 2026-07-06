"""
warden/tests/test_contact_endpoint.py
Covers /api/contact after its Phase-3 extraction to warden/api/contact.py.
SMTP is unconfigured in tests -> handler logs and returns {"ok": True}.
"""
from __future__ import annotations


def test_contact_returns_ok_without_smtp(client, monkeypatch):
    monkeypatch.delenv("SMTP_HOST", raising=False)
    monkeypatch.delenv("SMTP_USER", raising=False)
    resp = client.post("/api/contact", json={
        "name": "Ada", "email": "ada@example.com",
        "subject": "hello", "message": "hi there", "company": "ACME",
    })
    assert resp.status_code == 200
    assert resp.json() == {"ok": True}


def test_contact_validates_required_fields(client):
    resp = client.post("/api/contact", json={"name": "only-name"})
    assert resp.status_code == 422


def test_contact_router_is_standalone():
    """The extracted router must not import warden.main."""
    import ast
    import inspect

    from warden.api import contact
    tree = ast.parse(inspect.getsource(contact))
    mods: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            mods.append(node.module)
    assert "warden.main" not in mods
