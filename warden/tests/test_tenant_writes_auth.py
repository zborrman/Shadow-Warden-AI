"""
Anonymous corpus and tenant-data writes (2026-07-29).

Final slice of the write-method audit, after test_write_method_audit.py (empty
bodies), test_security_control_writes_auth.py (security controls) and
test_money_writes_auth.py (money and identity).

The sharpest one here is corpus poisoning:

  POST /sep/model-bundles/{ueciid}/activate

`/import` authenticates in-body — `import_bundle()` verifies an HMAC over the
bundle using a `resolve_key()`-derived key, so a forged bundle is rejected.
`/activate` did not. It takes only a `ueciid` and calls
`EvolutionEngine.add_examples()`, hot-loading that bundle's rules into the live
detection corpus. Its docstring says "called after human-in-the-loop approval",
but nothing enforced the approval *or* a caller identity — the protected half of
the pair sat next to an unprotected one.

The rest is cross-tenant data:

  /compliance/frameworks/{tenant_id}   tenant_id is a PATH param bound to nothing
  /community/posts, /comment, /members, DELETE /posts/{id}
  /obsidian/share                      publishes into a caller-named community

Both tenant helpers were pseudo-authentication: `community._tenant()` reads an
X-Tenant-ID header defaulting to "default", and `obsidian._get_tenant()` is not
even a header — it is a query parameter. Each returns whatever the caller says.
"""

from __future__ import annotations

import pytest


@pytest.fixture
def _client(monkeypatch):
    import warden.auth_guard as ag

    monkeypatch.setattr(ag, "_VALID_KEY", "tenant-key", raising=False)
    monkeypatch.setattr(ag, "_KEYS_PATH", "", raising=False)

    from fastapi.testclient import TestClient

    import warden.main as m

    return TestClient(m.app, raise_server_exceptions=False)


KEY = {"X-API-Key": "tenant-key"}

WRITES = [
    ("post", "/sep/model-bundles/SEP-abc/activate", {}),
    ("post", "/compliance/frameworks/victim", {"name": "n"}),
    ("put", "/compliance/frameworks/victim/F1", {"name": "n"}),
    ("delete", "/compliance/frameworks/victim/F1", None),
    ("patch", "/compliance/frameworks/victim/F1/controls/C1", {"status": "x"}),
    ("post", "/community/posts", {"author_id": "a", "content": "c"}),
    ("post", "/community/posts/from-obsidian", {"author_id": "a", "note_content": "c"}),
    ("post", "/community/posts/P1/comment", {"author_id": "a", "content": "c"}),
    ("delete", "/community/posts/P1", None),
    ("post", "/community/members", {"user_id": "u", "display_name": "d"}),
    ("post", "/obsidian/share", {"content": "x", "display_name": "d", "community_id": "c"}),
]


@pytest.mark.parametrize("verb,path,body", WRITES)
def test_corpus_and_tenant_writes_require_auth(_client, verb, path, body):
    kwargs = {"json": body} if body is not None else {}
    assert getattr(_client, verb)(path, **kwargs).status_code == 401, (
        f"{verb.upper()} {path} executed without credentials."
    )


def test_detection_corpus_cannot_be_loaded_anonymously(_client):
    """
    activate_bundle() calls EvolutionEngine.add_examples(), so this endpoint
    writes into the live jailbreak-detection corpus. The paired /import verifies
    an HMAC; this one verified nothing.
    """
    assert (
        _client.post("/sep/model-bundles/SEP-poison/activate").status_code == 401
    )


def test_another_tenants_compliance_data_is_not_writable(_client):
    """
    tenant_id is a path parameter with nothing binding it to the caller, so every
    write was CRUD on an arbitrary customer's compliance frameworks — including
    DELETE.
    """
    for verb, path, body in [
        ("post", "/compliance/frameworks/some-other-customer", {"name": "x"}),
        ("delete", "/compliance/frameworks/some-other-customer/F1", None),
    ]:
        kwargs = {"json": body} if body is not None else {}
        assert getattr(_client, verb)(path, **kwargs).status_code == 401


def test_another_tenants_post_cannot_be_deleted(_client):
    assert _client.delete("/community/posts/someone-elses-post").status_code == 401


def test_public_surface_stays_open(_client):
    """
    The complement. These are the product's free/demo surface and the Obsidian
    plugin's main use — its API key setting is documented as optional, so gating
    the scanners would break existing installs. Kept public by decision; see
    docs/anonymous-route-audit-2026-07-29.md.
    """
    assert _client.get("/compliance/frameworks/t").status_code != 401
    assert _client.post("/obsidian/scan", json={"content": "x"}).status_code != 401
    assert _client.post("/obsidian/ai-filter", json={"prompt": "x"}).status_code != 401
    assert (
        _client.post("/scan/email", json={"subject": "s", "body": "b"}).status_code != 401
    )
    assert (
        _client.post(
            "/api/contact",
            json={"name": "n", "email": "e", "subject": "s", "message": "m"},
        ).status_code
        != 401
    )


def test_tenant_helpers_are_not_authentication():
    """
    Structural note, pinned so nobody mistakes these for a gate again: both
    helpers return whatever the caller supplies, and `_get_tenant` is a query
    parameter rather than a header.
    """
    from warden.api.community import _tenant
    from warden.api.obsidian import _get_tenant

    assert _tenant("attacker-chosen") == "attacker-chosen"
    assert _get_tenant("attacker-chosen") == "attacker-chosen"
