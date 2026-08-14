"""
Community Hub API — unified /communities router.
Covers: CRUD, membership, data upload, document scan, peering,
network federation, analytics, compliance, and evolution sharing.
"""
from __future__ import annotations

import time
from typing import Any, NoReturn

from fastapi import APIRouter, Body, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from warden.auth_guard import AuthResult, require_api_key

# ── Authentication ───────────────────────────────────────────────────────────
#
# Router-level dependency: EVERY route here requires a valid API key.
#
# This module previously declared zero dependencies across 34 routes. 28 of them
# were live (the other 6 were shadowed by warden/communities/router.py and have
# since been deleted — see the note below), and all 28 were reachable
# anonymously in production — verified 2026-07-29:
#
#   GET /communities/networks/list                 -> 200 with no credentials
#   GET /communities/{id}/analytics                -> 200
#   GET /communities/{id}/compliance               -> 200
#   GET /communities/{id}/data                     -> 200
#   GET /communities/{id}/peers                    -> 200
#   GET /communities/{id}/evolution/bundles        -> 200
#   GET /communities/member/{tenant_id}/memberships-> 200
#
# The write surface on the same router is the more serious half: DELETE a
# community, PUT its settings, PATCH it, change a member's role, upload/delete
# files, and approve/import evolution bundles.
#
# There is no global auth middleware in warden/main.py — the only two http
# middlewares attach a request id and set security headers — so an absent
# per-route dependency means genuinely no authentication, not a gap in a
# blanket rule.
#
# Per-tenant authorization (vuln-0002 / CWE-639, 2026-08-14): every
# community-scoped handler now injects `auth: AuthResult = Depends(require_api_key)`
# and calls `_require_role(...)` (mutations) or `_require_read(...)` (reads) to
# bind the authenticated tenant to the target community before acting. Identity
# for actor fields (uploader/publisher/reviewer/requester) comes from
# `auth.tenant_id`, never from a client-supplied path/query/body value. The
# router-level dependency below still guarantees baseline authentication on every
# route (including the global /stats and /networks/* handlers).
router = APIRouter(
    prefix="/communities",
    tags=["Community Hub"],
    dependencies=[Depends(require_api_key)],
)

# TWO ROUTERS SHARE THE /communities PREFIX — see the note below before adding a route.
#
# TWO ROUTERS SHARE THE /communities PREFIX. `warden/communities/router.py` is
# registered first, so for any path both define, its handler serves and the one
# here never runs. Six such handlers used to live in this file — create/list
# community, get community, list/add/remove member — and they were unreachable
# dead code with weaker auth than the versions that actually answer (no tier
# gate, and identity taken from the request body rather than the API key). They
# were removed rather than left as a trap for the next reader, or as a latent
# downgrade if the mount order ever changed. Add a route here only after
# checking it is not already claimed there.


# ── Pydantic models ────────────────────────────────────────────

class PatchCommunityIn(BaseModel):
    name: str | None = Field(default=None, max_length=80)
    description: str | None = Field(default=None, max_length=600)


class UpdateSettingsIn(BaseModel):
    visibility: str | None = None
    join_policy: str | None = None
    extra: dict = Field(default_factory=dict)


class JoinIn(BaseModel):
    tenant_id: str
    display_name: str = ""


class UpdateRoleIn(BaseModel):
    role: str


class CreateNetworkIn(BaseModel):
    name: str = Field(..., min_length=2, max_length=80)
    description: str = ""
    creator_tenant_id: str


class PeerIn(BaseModel):
    target_community_id: str
    policy: str = "MIRROR_ONLY"   # MIRROR_ONLY / REWRAP_ALLOWED / FULL_SYNC


class ShareRuleIn(BaseModel):
    publisher_tenant_id: str
    rule_type: str = "jailbreak_signature"
    rule_content: str = Field(..., min_length=4, max_length=4000)


# ── Helpers ────────────────────────────────────────────────────

def _404(what: str = "Community") -> NoReturn:
    raise HTTPException(status_code=404, detail=f"{what} not found")


def _403(msg: str = "Not authorized") -> NoReturn:
    raise HTTPException(status_code=403, detail=msg)


def _dc(obj: Any) -> dict:
    from dataclasses import asdict
    return asdict(obj) if hasattr(obj, "__dataclass_fields__") else dict(obj)


# ── Per-tenant authorization (vuln-0002 / CWE-639) ─────────────────────────────
#
# The router-level `require_api_key` only proves *who* is calling (authn). Every
# community-scoped handler must additionally bind that identity to the target
# {community_id} (authz), or any authenticated tenant can read/mutate/take over
# another tenant's community. Never trust a tenant identifier taken from the
# path, query, or body — use `auth.tenant_id`.

_ROLE_RANK = {"observer": 0, "member": 1, "admin": 2, "owner": 3}


def _caller_role(community_id: str, tenant_id: str) -> tuple[str | None, Any]:
    """(role, community) for *tenant_id* in *community_id*; role None if not a
    member. The community creator is always treated as ``owner`` even without an
    explicit members row. 404s if the community does not exist."""
    from warden.communities.community_factory import get_community
    from warden.communities.membership import get_member
    c = get_community(community_id)
    if c is None:
        _404()
    if c.creator_tenant_id == tenant_id:
        return "owner", c
    m = get_member(community_id, tenant_id)
    if m is not None and getattr(m, "status", "active") == "active":
        return m.role, c
    return None, c


def _require_role(community_id: str, auth: AuthResult, min_role: str) -> tuple[str, Any]:
    """Enforce that the caller holds at least *min_role* in the community."""
    role, c = _caller_role(community_id, auth.tenant_id)
    if role is None or _ROLE_RANK.get(role, -1) < _ROLE_RANK[min_role]:
        _403(f"Requires '{min_role}' role in this community")
    return role, c


def _require_read(community_id: str, auth: AuthResult) -> Any:
    """Members may read; non-members may read only ``public`` communities."""
    role, c = _caller_role(community_id, auth.tenant_id)
    if role is None and getattr(c, "visibility", "private") != "public":
        _403("You are not a member of this community")
    return c


# ══════════════════════════════════════════════════════════════
# 1. Community CRUD
# ══════════════════════════════════════════════════════════════

@router.get("/stats", summary="Global community stats")
def community_stats():
    from warden.communities.community_factory import get_community_stats
    return get_community_stats()


@router.patch("/{community_id}", summary="Patch community name / description")
def patch_community(community_id: str, req: PatchCommunityIn,
                    auth: AuthResult = Depends(require_api_key)):
    _require_role(community_id, auth, "admin")
    from warden.communities.community_factory import patch_community as _p
    if not _p(community_id, name=req.name, description=req.description):
        raise HTTPException(status_code=404, detail="Community not found or nothing to update")
    return {"status": "updated", "community_id": community_id}


@router.put("/{community_id}/settings", summary="Update community settings")
def update_settings(community_id: str, req: UpdateSettingsIn,
                    auth: AuthResult = Depends(require_api_key)):
    _, c = _require_role(community_id, auth, "admin")
    from warden.communities.community_factory import update_community_settings
    settings = {**c.settings, **req.extra}
    if req.visibility:
        settings["visibility"] = req.visibility
    if req.join_policy:
        settings["join_policy"] = req.join_policy
    update_community_settings(community_id, settings)
    return {"status": "updated", "community_id": community_id}


@router.delete("/{community_id}", summary="Delete community")
def delete_community(community_id: str, auth: AuthResult = Depends(require_api_key)):
    # Owner-only. Identity comes from the API key, never a client-supplied param.
    _require_role(community_id, auth, "owner")
    from warden.communities.community_factory import delete_community as _d
    if not _d(community_id, auth.tenant_id):
        raise HTTPException(status_code=403, detail="Not authorized or community not found")
    return {"status": "deleted", "community_id": community_id}


# ══════════════════════════════════════════════════════════════
# 2. Membership
# ══════════════════════════════════════════════════════════════

@router.post("/{community_id}/join", status_code=201, summary="Join community")
def join_community(community_id: str, req: JoinIn,
                   auth: AuthResult = Depends(require_api_key)):
    # A caller may only join AS ITSELF — never enrol another tenant.
    from warden.communities.community_factory import get_community
    from warden.communities.membership import add_member
    c = get_community(community_id)
    if not c:
        _404()
    if c.join_policy == "invite":
        _403("This community is invite-only; use the knock-and-verify flow")
    m = add_member(community_id, auth.tenant_id, role="member", display_name=req.display_name)
    return _dc(m)


@router.put("/{community_id}/members/{member_id}", summary="Update member role")
def update_member_role(community_id: str, member_id: str, req: UpdateRoleIn,
                       auth: AuthResult = Depends(require_api_key)):
    caller_role, _ = _require_role(community_id, auth, "admin")
    from warden.communities.membership import get_member_by_id
    from warden.communities.membership import update_member_role as _ur
    target = get_member_by_id(member_id)
    if target is None or target.community_id != community_id:
        raise HTTPException(status_code=400, detail="Invalid role or member not found")
    # Privilege-escalation guard: only an owner may grant or revoke the owner role.
    if (req.role == "owner" or target.role == "owner") and caller_role != "owner":
        _403("Only an owner can assign or change the owner role")
    if not _ur(community_id, member_id, req.role):
        raise HTTPException(status_code=400, detail="Invalid role or member not found")
    return {"status": "updated", "member_id": member_id, "role": req.role}


@router.get("/member/{tenant_id}/memberships", summary="Get tenant's communities")
def tenant_memberships(tenant_id: str, auth: AuthResult = Depends(require_api_key)):
    # A tenant may only enumerate its OWN memberships.
    if tenant_id != auth.tenant_id:
        _403("You may only list your own memberships")
    from warden.communities.membership import get_member_communities
    return get_member_communities(auth.tenant_id)


# ══════════════════════════════════════════════════════════════
# 3. Shared Data
# ══════════════════════════════════════════════════════════════

@router.post("/{community_id}/data/upload", status_code=201, summary="Upload file")
async def upload_file(
    community_id: str,
    context: str = Form(default=""),
    file: UploadFile = File(...),
    auth: AuthResult = Depends(require_api_key),
):
    _require_role(community_id, auth, "member")
    from warden.communities.community_data import register_file
    content = await file.read()
    cf = register_file(
        community_id=community_id,
        uploader_tenant_id=auth.tenant_id,
        filename=file.filename or "upload",
        content_type=file.content_type or "application/octet-stream",
        size_bytes=len(content),
        content=content,
        context=context,
    )
    return _dc(cf)


@router.get("/{community_id}/data", summary="List community files")
def list_data(community_id: str, auth: AuthResult = Depends(require_api_key)):
    _require_read(community_id, auth)
    from warden.communities.community_data import list_files
    return [_dc(f) for f in list_files(community_id)]


@router.get("/{community_id}/data/{file_id}", summary="Get file metadata")
def get_file_meta(community_id: str, file_id: str,
                  auth: AuthResult = Depends(require_api_key)):
    _require_read(community_id, auth)
    from warden.communities.community_data import get_file, increment_download
    f = get_file(file_id)
    if not f or f.community_id != community_id:
        _404("File")
    increment_download(file_id)
    return _dc(f)


@router.delete("/{community_id}/data/{file_id}", summary="Delete file")
def delete_file(community_id: str, file_id: str,
                auth: AuthResult = Depends(require_api_key)):
    _require_role(community_id, auth, "member")
    from warden.communities.community_data import delete_file as _df
    if not _df(file_id, auth.tenant_id):
        raise HTTPException(status_code=403, detail="Not authorized or file not found")
    return {"status": "deleted", "file_id": file_id}


# ══════════════════════════════════════════════════════════════
# 4. Document Intelligence
# ══════════════════════════════════════════════════════════════

@router.post("/{community_id}/documents/scan", status_code=201,
             summary="Scan document via Document Intelligence")
async def scan_document(
    community_id: str,
    file: UploadFile = File(...),
    auth: AuthResult = Depends(require_api_key),
):
    _require_role(community_id, auth, "member")
    uploader_tenant_id = auth.tenant_id
    content = await file.read()
    result: dict[str, Any] = {
        "community_id": community_id,
        "filename": file.filename,
    }

    # Convert via Document Intelligence
    md_text = ""
    try:
        from warden.document_intel.converter import MarkItDownConverter
        conv = MarkItDownConverter()
        md_text = conv.convert_bytes(content, filename=file.filename or "upload.bin").markdown
        result["markdown_chars"] = len(md_text)
        result["preview"] = md_text[:400]
    except Exception as exc:
        result["conversion_error"] = str(exc)
        md_text = content.decode("utf-8", errors="replace")

    # Filter scan
    try:
        import httpx
        resp = httpx.post(
            "http://localhost:8001/filter",
            json={"text": md_text[:4000], "tenant_id": uploader_tenant_id},
            timeout=5.0,
        )
        if resp.status_code == 200:
            fd = resp.json()
            result["blocked"] = fd.get("blocked", False)
            result["score"] = fd.get("score", 0.0)
            result["verdict"] = fd.get("verdict", "ALLOW")
    except Exception as exc:
        result["filter_error"] = str(exc)

    # Register file in community data store
    try:
        from warden.communities.community_data import register_file
        cf = register_file(
            community_id, uploader_tenant_id,
            file.filename or "document",
            file.content_type or "application/octet-stream",
            len(content), content,
        )
        result["file_id"] = cf.file_id
        result["ueciid"] = cf.ueciid
    except Exception:
        pass

    # Auto-log incident for blocked/high-risk documents
    if result.get("blocked") or result.get("score", 0) > 0.7:
        try:
            from warden.communities.incident_register import log_incident
            log_incident(
                tenant_id=uploader_tenant_id,
                title=f"Document threat: {file.filename}",
                severity="HIGH" if result.get("blocked") else "MEDIUM",
                category="COMPLIANCE",
                description=f"Document scan score: {result.get('score', 0):.2f}",
                community_id=community_id,
            )
        except Exception:
            pass

    return result


# ══════════════════════════════════════════════════════════════
# 5. Peering / Federation
# ══════════════════════════════════════════════════════════════

@router.get("/{community_id}/peers", summary="List peerings")
def get_peers(community_id: str, auth: AuthResult = Depends(require_api_key)):
    _require_read(community_id, auth)
    try:
        from warden.communities.peering import list_peerings
        peerings = list_peerings(community_id)
        return [_dc(p) for p in peerings]
    except Exception:
        return []


@router.post("/{community_id}/peer", status_code=201, summary="Request peering")
def request_peering(community_id: str, req: PeerIn,
                    auth: AuthResult = Depends(require_api_key)):
    _require_role(community_id, auth, "admin")
    try:
        from warden.communities.peering import initiate_peering
        result = initiate_peering(community_id, req.target_community_id, req.policy)
        return result if isinstance(result, dict) else _dc(result)
    except AttributeError:
        return {
            "status": "pending",
            "source_community_id": community_id,
            "target_community_id": req.target_community_id,
            "policy": req.policy,
            "initiated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


# ══════════════════════════════════════════════════════════════
# 6. Networks (meta-communities)
# ══════════════════════════════════════════════════════════════

@router.get("/networks/list", summary="List networks")
def list_networks():
    from warden.communities.network import list_networks as _ln
    return [_dc(n) for n in _ln()]


@router.post("/networks/create", status_code=201, summary="Create network")
def create_network(req: CreateNetworkIn, auth: AuthResult = Depends(require_api_key)):
    # Creator identity comes from the API key, not the request body.
    from warden.communities.network import create_network as _cn
    return _dc(_cn(req.name, req.description, auth.tenant_id))


@router.get("/networks/{network_id}", summary="Get network")
def get_network(network_id: str):
    from warden.communities.network import get_network as _gn
    n = _gn(network_id)
    if not n:
        _404("Network")
    result = _dc(n)
    from warden.communities.network import get_network_stats
    result["stats"] = get_network_stats(network_id)
    return result


@router.post("/networks/{network_id}/join", summary="Community joins network")
def network_join(network_id: str, community_id: str = Body(..., embed=True)):
    from warden.communities.network import join_network
    join_network(network_id, community_id)
    return {"status": "joined", "network_id": network_id, "community_id": community_id}


@router.get("/networks/{network_id}/communities", summary="Network community list")
def network_communities(network_id: str):
    from warden.communities.network import list_network_communities
    return list_network_communities(network_id)


# ══════════════════════════════════════════════════════════════
# 7. Analytics
# ══════════════════════════════════════════════════════════════

@router.get("/{community_id}/analytics", summary="Community activity analytics")
def get_analytics(community_id: str, days: int = Query(7, ge=1, le=90),
                  auth: AuthResult = Depends(require_api_key)):
    _require_read(community_id, auth)
    result: dict[str, Any] = {
        "community_id": community_id,
        "period_days": days,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        from warden.communities.membership import list_members
        members = list_members(community_id)
        result["member_count"] = len(members)
        roles: dict[str, int] = {}
        for m in members:
            roles[m.role] = roles.get(m.role, 0) + 1
        result["member_roles"] = roles
    except Exception:
        result["member_count"] = 0

    try:
        from warden.communities.community_data import get_data_stats
        result["data"] = get_data_stats(community_id)
    except Exception:
        result["data"] = {}

    try:
        from warden.communities.community_evolution import get_evolution_stats
        result["evolution"] = get_evolution_stats(community_id)
    except Exception:
        result["evolution"] = {}

    try:
        from warden.communities.community_compliance import get_community_compliance
        cr = get_community_compliance(community_id)
        result["compliance_score"] = cr.score
        result["compliance_status"] = cr.status
    except Exception:
        result["compliance_score"] = None

    return result


# ══════════════════════════════════════════════════════════════
# 8 & 9. Compliance
# ══════════════════════════════════════════════════════════════

@router.get("/{community_id}/compliance", summary="Compliance posture report")
def get_compliance(community_id: str, auth: AuthResult = Depends(require_api_key)):
    _require_read(community_id, auth)
    from warden.communities.community_compliance import get_community_compliance
    return _dc(get_community_compliance(community_id))


_CTRL_COLORS = {"PASS": "#34d399", "FAIL": "#f87171", "WARN": "#fbbf24"}
_STATUS_COLORS = {"COMPLIANT": "#34d399", "PARTIAL": "#fbbf24", "NON_COMPLIANT": "#f87171"}


def _ctrl_color(status: str) -> str:
    return _CTRL_COLORS.get(status, "#94a3b8")


@router.post("/{community_id}/compliance/export", summary="Export HTML compliance report")
def export_compliance(community_id: str, auth: AuthResult = Depends(require_api_key)):
    _require_read(community_id, auth)
    from warden.communities.community_compliance import get_community_compliance
    report = get_community_compliance(community_id)
    sc = _STATUS_COLORS.get(report.status, "#94a3b8")
    rows = "".join(
        f'<tr><td>{c["control"]}</td>'
        f'<td style="color:{_ctrl_color(c["status"])}">{c["status"]}</td>'
        f'<td>{c["detail"]}</td></tr>'
        for c in report.controls
    )
    gaps_html = (
        "<h2>Remediation Required</h2><ul>"
        + "".join(f'<li><strong>{g["control"]}</strong>: {g["detail"]}</li>' for g in report.gaps)
        + "</ul>"
    ) if report.gaps else ""
    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Community Compliance — {community_id}</title>
<style>
  body{{font-family:system-ui,-apple-system,sans-serif;padding:48px;
       background:#07090f;color:#e2e8f0;max-width:900px;margin:auto}}
  h1{{color:#818cf8;margin-bottom:4px}}code{{color:#818cf8;font-size:.85em}}
  .score{{font-size:2.4em;font-weight:700;color:{sc}}}
  table{{width:100%;border-collapse:collapse;margin-top:24px}}
  th{{text-align:left;padding:10px 12px;border-bottom:2px solid #1e293b;
      font-size:.75em;text-transform:uppercase;letter-spacing:.08em;color:#475569}}
  td{{padding:10px 12px;border-bottom:1px solid #0f172a;font-size:.875em}}
  h2{{color:#fbbf24;margin-top:32px}}li{{margin:6px 0;color:#94a3b8}}
</style></head><body>
<h1>Community Compliance Report</h1>
<p>Community: <code>{community_id}</code></p>
<p class="score">{report.score:.0%} <span style="font-size:.45em;color:#475569">{report.status}</span></p>
<p style="color:#475569;font-size:.8em">Generated: {report.generated_at}</p>
<table><thead><tr><th>Control</th><th>Status</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody></table>
{gaps_html}
</body></html>"""
    return HTMLResponse(content=html, headers={"Content-Disposition": f'inline; filename="compliance-{community_id}.html"'})


# ══════════════════════════════════════════════════════════════
# 10 & 11. AI Evolution
# ══════════════════════════════════════════════════════════════

@router.post("/{community_id}/evolution/share", status_code=201,
             summary="Share anonymised evolution rule")
def share_evolution_rule(community_id: str, req: ShareRuleIn,
                         auth: AuthResult = Depends(require_api_key)):
    _require_role(community_id, auth, "member")
    from warden.communities.community_evolution import share_rule
    b = share_rule(community_id, auth.tenant_id, req.rule_type, req.rule_content)
    return _dc(b)


@router.get("/{community_id}/evolution/bundles", summary="List evolution bundles")
def list_evolution_bundles(
    community_id: str,
    status: str | None = Query(None),
    auth: AuthResult = Depends(require_api_key),
):
    _require_read(community_id, auth)
    from warden.communities.community_evolution import list_bundles
    return [_dc(b) for b in list_bundles(community_id=community_id, status=status)]


@router.post("/{community_id}/evolution/bundles/{bundle_id}/approve",
             summary="Approve evolution bundle (human gate)")
def approve_bundle(
    community_id: str,
    bundle_id: str,
    auth: AuthResult = Depends(require_api_key),
):
    _require_role(community_id, auth, "admin")
    from warden.communities.community_evolution import approve_rule
    if not approve_rule(bundle_id, auth.tenant_id):
        _404("Bundle")
    return {"status": "approved", "bundle_id": bundle_id}


@router.post("/{community_id}/evolution/bundles/{bundle_id}/reject",
             summary="Reject evolution bundle")
def reject_bundle(community_id: str, bundle_id: str,
                  auth: AuthResult = Depends(require_api_key)):
    _require_role(community_id, auth, "admin")
    from warden.communities.community_evolution import reject_rule
    if not reject_rule(bundle_id):
        _404("Bundle")
    return {"status": "rejected", "bundle_id": bundle_id}


@router.post("/{community_id}/evolution/bundles/{bundle_id}/import",
             summary="Import approved bundle into local evolution engine")
def import_bundle(community_id: str, bundle_id: str,
                  auth: AuthResult = Depends(require_api_key)):
    _require_role(community_id, auth, "admin")
    from warden.communities.community_evolution import import_rule
    if not import_rule(bundle_id, community_id):
        raise HTTPException(status_code=422, detail="Bundle not found or not yet approved")
    return {"status": "imported", "bundle_id": bundle_id, "community_id": community_id}


@router.get("/{community_id}/evolution/stats", summary="Evolution sharing stats")
def evolution_stats(community_id: str, auth: AuthResult = Depends(require_api_key)):
    _require_read(community_id, auth)
    from warden.communities.community_evolution import get_evolution_stats
    return get_evolution_stats(community_id)
