"""
warden/tests/test_tenant_isolation.py — the H-5 guard.

A route must not take the tenant it acts on from the caller. Detection lives in
``warden/hooks/tenant_isolation.py``; this module is the merge gate, because CI
runs pytest and not pre-commit.

The hook this replaces looked for SQLAlchemy ``.filter()`` calls in
``warden/api/`` that did not mention ``tenant_id``. ``warden/api/`` uses raw
SQLite, so it found nothing on every run — and it exited 0 unconditionally, so
it could not have blocked a finding if it had made one. Meanwhile the defect that
actually shipped (#444, SW-11..16) was two new routes that took ``tenant_id`` as
a query parameter: any caller could read any tenant's trade volume by naming it.

When this guard was written, **175 routes in 38 files** had that shape. They are
recorded in ``tenant_isolation_baseline.json`` as debt, not as accepted
exceptions — unlike the H-7 baseline, nothing here has a reason to stay. Most
are latent while production runs a single key (every caller resolves to tenant
``default``) and become cross-tenant reads, writes or worse the moment a second
tenant is onboarded. The baseline may only shrink:

* a new route with the shape fails ``test_no_new_claimed_tenant_routes``;
* a fixed route that is still listed fails ``test_the_baseline_has_no_stale_entries``,
  so the floor moves down with every fix instead of leaving slack behind it.

Regenerate after a genuine reduction (a new finding fails before it can write):

    UPDATE_TENANT_ISOLATION_BASELINE=1 pytest warden/tests/test_tenant_isolation.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from warden.hooks.tenant_isolation import BASELINE, scan_file, scan_source

_WARDEN = Path(__file__).resolve().parent.parent
_REPO = _WARDEN.parent


def _scan_tree() -> list:
    findings = []
    for py in sorted(_WARDEN.rglob("*.py")):
        rel = py.relative_to(_REPO).as_posix()
        if "/tests/" in rel or "/hooks/" in rel:
            continue
        findings.extend(scan_file(py, rel))
    return findings


def _baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def test_no_new_claimed_tenant_routes() -> None:
    findings = _scan_tree()
    keys = {f.key for f in findings}

    if os.getenv("UPDATE_TENANT_ISOLATION_BASELINE") == "1":
        new = keys - set(_baseline()["routes"])
        assert not new, "refusing to baseline new findings:\n  " + "\n  ".join(sorted(new))
        BASELINE.write_text(
            json.dumps({"total": len(keys), "routes": sorted(keys)}, indent=2) + "\n",
            encoding="utf-8",
        )
        pytest.skip("baseline rewritten")

    baseline = set(_baseline()["routes"])
    leaks = [f for f in findings if f.key not in baseline]
    assert not leaks, (
        "route takes its tenant from the request:\n  "
        + "\n  ".join(str(f) for f in leaks)
        + "\n\nResolve the tenant from auth — `auth: AuthResult = Depends(require_api_key)` "
          "then `auth.tenant_id` — or, when the path names a tenant on purpose, depend on "
          "`require_tenant_owner_or_admin`. A claimed tenant is anyone's tenant."
    )


def test_the_baseline_has_no_stale_entries() -> None:
    """A fixed route must leave the baseline, or the slack is reusable."""
    stale = set(_baseline()["routes"]) - {f.key for f in _scan_tree()}
    assert not stale, (
        "fixed (or moved) but still baselined — regenerate with "
        "UPDATE_TENANT_ISOLATION_BASELINE=1:\n  " + "\n  ".join(sorted(stale))
    )


def test_the_recorded_total_matches_the_list() -> None:
    baseline = _baseline()
    assert baseline["total"] == len(baseline["routes"]) == len(set(baseline["routes"]))


# ── The guard must be able to fire ────────────────────────────────────────────
# The previous hook was a control present and permitting everyone. These pin
# that this one catches the shapes that exist in the tree.

_HEAD = "from fastapi import APIRouter, Depends, Header, Query\nrouter = APIRouter()\n"


@pytest.mark.parametrize("body", [
    # the #444 shape: tenant as a query parameter on an authenticated route
    """
    @router.get("/trust/leaderboard", dependencies=[Depends(require_api_key)])
    async def lb(tenant_id: str = Query(...)):
        return load(tenant_id)
    """,
    # path parameter, auth present but never compared (onboarding rotate-key)
    """
    @router.post("/onboard/{tenant_id}/rotate-key")
    async def rotate(tenant_id: str, auth: AuthResult = Depends(require_api_key)):
        return rotate_key(tenant_id)
    """,
    # header-claimed identity
    """
    @router.get("/billing/status")
    async def status(x_tenant_id: str = Header("default")):
        return billing(x_tenant_id)
    """,
    # literal default — the caller overrides it by sending ?tenant_id=
    """
    @router.get("/posts")
    def posts(tenant_id: str = "default"):
        return feed(tenant_id)
    """,
    # a feature/tier gate is not an ownership check
    """
    _Gate = Depends(require_feature("x"))
    @router.get("/vendors", dependencies=[_Gate])
    async def vendors(tenant_id: str):
        return list_vendors(tenant_id)
    """,
    # comparing against something other than an authenticated tenant binds nothing
    """
    @router.get("/x/{tenant_id}")
    async def x(tenant_id: str):
        if tenant_id == "":
            raise ValueError
        return load(tenant_id)
    """,
])
def test_scanner_catches_a_claimed_tenant(body: str) -> None:
    assert scan_source(_HEAD + textwrap.dedent(body), "x.py"), "not caught"


@pytest.mark.parametrize("body", [
    # the fix: tenant comes from auth
    """
    @router.get("/vendors")
    async def vendors(auth: AuthResult = Depends(require_api_key)):
        return list_vendors(auth.tenant_id)
    """,
    # the tenant parameter itself is a dependency
    """
    @router.get("/vendors")
    async def vendors(tenant_id: str = Depends(get_tenant_id)):
        return list_vendors(tenant_id)
    """,
    # ownership is checked by the route's dependency
    """
    @router.delete("/purge/tenant/{tenant_id}",
                   dependencies=[Depends(require_tenant_owner_or_admin)])
    async def purge(tenant_id: str):
        return purge_all(tenant_id)
    """,
    # operator-only route acting on a named tenant, via a module-level alias
    """
    _ADMIN = Depends(_require_admin)
    @router.post("/tenants/{tenant_id}/grant", dependencies=[_ADMIN])
    async def grant(tenant_id: str):
        return do_grant(tenant_id)
    """,
    # explicit comparison in the body
    """
    @router.get("/onboard/{tenant_id}")
    async def get_t(tenant_id: str, auth: AuthResult = Depends(require_api_key)):
        if auth.tenant_id != tenant_id:
            raise HTTPException(403)
        return load(tenant_id)
    """,
    # not a route at all
    """
    def helper(tenant_id: str = "default"):
        return tenant_id
    """,
])
def test_scanner_spares_a_bound_tenant(body: str) -> None:
    assert not scan_source(_HEAD + textwrap.dedent(body), "x.py")


def test_router_level_admin_dependency_binds_every_route() -> None:
    src = textwrap.dedent("""
        from fastapi import APIRouter, Depends
        router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin_only)])
        @router.get("/tenants/{tenant_id}")
        async def t(tenant_id: str):
            return load(tenant_id)
    """)
    assert not scan_source(src, "x.py")


# ── The pre-commit hook blocks ────────────────────────────────────────────────

def test_the_hook_exits_nonzero_on_a_new_finding(tmp_path: Path) -> None:
    """The old hook returned 0 unconditionally; pin that this one does not."""
    leaky = tmp_path / "warden" / "api" / "leaky_probe.py"
    leaky.parent.mkdir(parents=True)
    leaky.write_text(
        _HEAD + "@router.get('/x')\nasync def x(tenant_id: str):\n    return tenant_id\n",
        encoding="utf-8",
    )
    hook = _WARDEN / "hooks" / "tenant_isolation.py"
    res = subprocess.run(
        [sys.executable, str(hook), "warden/api/leaky_probe.py"],
        cwd=tmp_path, capture_output=True, text=True, timeout=60,
    )
    assert res.returncode == 1, res.stdout + res.stderr
    assert "leaky_probe.py" in res.stdout


def test_the_hook_passes_a_baselined_file() -> None:
    hook = _WARDEN / "hooks" / "tenant_isolation.py"
    some = sorted(_baseline()["routes"])[0].split("::")[0]
    res = subprocess.run(
        [sys.executable, str(hook), some],
        cwd=_REPO, capture_output=True, text=True, timeout=60,
    )
    assert res.returncode == 0, res.stdout + res.stderr


def test_the_hook_is_wired_as_blocking() -> None:
    cfg = (_REPO / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    block = cfg.split("id: tenant-isolation", 1)[1].split("- id:", 1)[0]
    assert "advisory" not in block.lower()
    assert "files: ^warden/" in block and "files: ^warden/api/" not in block
