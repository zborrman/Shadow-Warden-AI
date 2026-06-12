"""
Streamlit Community Hub — 7 tabs: My Communities, Explore,
Members, Data, Compliance, Evolution, Settings.
"""
from __future__ import annotations

import os
import time
from datetime import datetime

import httpx
import streamlit as st


def fmt_date(iso: str) -> str:
    try:
        d = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return d.strftime("%d/%m/%y")
    except Exception:
        return iso[:10] if len(iso) >= 10 else iso


def st_toast(msg: str, icon: str = "✅") -> None:
    try:
        st.toast(msg, icon=icon)
    except AttributeError:
        st.success(f"{icon} {msg}")

BASE = os.getenv("WARDEN_API_URL", "http://localhost:8001")
HEADERS = {"X-API-Key": os.getenv("WARDEN_API_KEY", "")}
TENANT = os.getenv("DEFAULT_TENANT_ID", "demo-tenant")

st.set_page_config(page_title="Community Hub", page_icon="🌐", layout="wide")

st.markdown("""
<style>
  [data-testid="stAppViewContainer"] { background: #07090f; }
  [data-testid="stSidebar"] { background: #0a0f1e; }
  .block-container { padding-top: 1.5rem; }
  .metric-card {
    background: rgba(129,140,248,.06); border: 1px solid rgba(129,140,248,.15);
    border-radius: 12px; padding: 18px; margin-bottom: 10px;
  }
  .badge-green { color: #34d399; font-weight: 600; }
  .badge-amber { color: #fbbf24; font-weight: 600; }
  .badge-red   { color: #f87171; font-weight: 600; }
  .danger-zone {
    background: rgba(248,113,113,.05); border: 1px solid rgba(248,113,113,.2);
    border-radius: 8px; padding: 12px; margin-top: 8px;
  }
</style>
""", unsafe_allow_html=True)

st.title("🌐 Community Hub")
st.caption("Federated AI community management — create, govern, collaborate, comply.")

# ── Sidebar ────────────────────────────────────────────────────
with st.sidebar:
    st.header("Active Tenant")
    tenant_id = st.text_input("Tenant ID", value=TENANT)

    st.divider()
    if st.button("🔄 Refresh All"):
        st.cache_data.clear()
        st.rerun()


# ── API helpers ────────────────────────────────────────────────

def api_get(path: str, **params) -> dict | list:
    try:
        r = httpx.get(f"{BASE}{path}", params=params, headers=HEADERS, timeout=8.0)
        if r.status_code == 200:
            return r.json()
    except Exception as exc:
        st.warning(f"API error: {exc}")
    return {}


def api_post(path: str, json: dict) -> dict:
    try:
        r = httpx.post(f"{BASE}{path}", json=json, headers=HEADERS, timeout=8.0)
        if r.status_code in (200, 201):
            return r.json()
        st.error(f"API {r.status_code}: {r.text[:200]}")
    except Exception as exc:
        st.error(f"API error: {exc}")
    return {}


def api_patch(path: str, json: dict) -> dict:
    try:
        r = httpx.patch(f"{BASE}{path}", json=json, headers=HEADERS, timeout=8.0)
        if r.status_code in (200, 201):
            return r.json()
        st.error(f"API {r.status_code}: {r.text[:200]}")
    except Exception as exc:
        st.error(f"API error: {exc}")
    return {}


def api_delete(path: str, **params) -> bool:
    try:
        r = httpx.delete(f"{BASE}{path}", params=params, headers=HEADERS, timeout=8.0)
        return r.status_code in (200, 204)
    except Exception as exc:
        st.error(f"API error: {exc}")
    return False


# ── Tabs ───────────────────────────────────────────────────────
tabs = st.tabs(["My Communities", "Explore", "Members", "Data", "Compliance", "Evolution", "Settings"])


# ────────────────────────────────────────────────────────────────
# Tab 1 — My Communities
# ────────────────────────────────────────────────────────────────
with tabs[0]:
    col_left, col_right = st.columns([2, 1])

    with col_right:
        st.subheader("Create Community")
        with st.form("create_form"):
            new_name = st.text_input("Name", placeholder="FinTech Alliance")
            new_desc = st.text_area("Description", height=80)
            new_vis  = st.selectbox("Visibility", ["private", "public"])
            new_pol  = st.selectbox("Join Policy", ["invite", "open", "approval"])
            if st.form_submit_button("Create →"):
                result = api_post("/communities", {
                    "name": new_name,
                    "description": new_desc,
                    "creator_tenant_id": tenant_id,
                    "visibility": new_vis,
                    "join_policy": new_pol,
                })
                if result.get("community_id"):
                    st.success(f"Created: `{result['community_id']}`")
                    time.sleep(0.6)
                    st.rerun()

    with col_left:
        st.subheader("My Communities")
        my_comms = api_get("/communities", tenant_id=tenant_id)
        if isinstance(my_comms, list) and my_comms:
            sorted_comms = sorted(my_comms, key=lambda x: x.get("created_at", ""), reverse=True)
            for c in sorted_comms:
                cid = c["community_id"]
                created = fmt_date(c.get("created_at", ""))
                with st.expander(f"🏛️ {c['name']}  ·  `{cid[:12]}…`  ·  {created}"):
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Members", c.get("member_count", "—"))
                    col_b.metric("Visibility", c.get("visibility", "—"))
                    col_c.metric("Join Policy", c.get("join_policy", "—"))

                    desc = c.get("description", "")
                    editing_key = f"editing_desc_{cid}"

                    if not st.session_state.get(editing_key):
                        st.caption(desc or "_No description_")
                        if st.button("✏️ Edit Description", key=f"edit_btn_{cid}"):
                            st.session_state[editing_key] = True
                            st.rerun()
                    else:
                        new_description = st.text_area(
                            "Description", value=desc, key=f"desc_ta_{cid}", height=80
                        )
                        ec1, ec2 = st.columns(2)
                        if ec1.button("Save", key=f"save_desc_{cid}"):
                            r = api_patch(f"/communities/{cid}", {"description": new_description})
                            if r.get("status") == "updated":
                                st.success("Description updated.")
                            st.session_state[editing_key] = False
                            st.rerun()
                        if ec2.button("Cancel", key=f"cancel_desc_{cid}"):
                            st.session_state[editing_key] = False
                            st.rerun()

                    if c.get("data_stats"):
                        ds = c["data_stats"]
                        st.caption(
                            f"📁 {ds.get('total_files', 0)} files · "
                            f"{ds.get('total_mb', 0):.1f} MB"
                        )

                    st.divider()
                    confirm_key = f"confirm_del_{cid}"
                    if not st.session_state.get(confirm_key):
                        if st.button("🗑️ Delete Community", key=f"del_btn_{cid}",
                                     type="secondary"):
                            st.session_state[confirm_key] = True
                            st.rerun()
                    else:
                        st.markdown('<div class="danger-zone">', unsafe_allow_html=True)
                        st.warning(f"Permanently delete **{c['name']}**? This cannot be undone.")
                        dc1, dc2 = st.columns(2)
                        if dc1.button("Yes, delete", key=f"yes_del_{cid}", type="primary"):
                            ok = api_delete(f"/communities/{cid}",
                                            requester_tenant_id=tenant_id)
                            st.session_state[confirm_key] = False
                            if ok:
                                st_toast("Community deleted.", "🗑️")
                                time.sleep(0.5)
                                st.rerun()
                            else:
                                st.error("Delete failed — you may not be the owner.")
                        if dc2.button("Cancel", key=f"cancel_del_{cid}"):
                            st.session_state[confirm_key] = False
                            st.rerun()
                        st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("No communities yet. Create one →")

    # Networks section
    st.divider()
    st.subheader("Networks (Meta-Communities)")
    net_col_l, net_col_r = st.columns([2, 1])

    with net_col_r, st.form("create_net"):
        nn = st.text_input("Network Name")
        nd = st.text_input("Description")
        if st.form_submit_button("Create Network"):
            api_post("/communities/networks/create", {
                "name": nn, "description": nd, "creator_tenant_id": tenant_id
            })
            st.rerun()

    with net_col_l:
        nets = api_get("/communities/networks/list")
        if isinstance(nets, list) and nets:
            for n in nets:
                st.write(f"**{n['name']}** · `{n['namespace']}` · {n['status']}")
        else:
            st.info("No networks yet.")


# ────────────────────────────────────────────────────────────────
# Tab 2 — Explore
# ────────────────────────────────────────────────────────────────
with tabs[1]:
    st.subheader("Explore Public Communities")
    search = st.text_input("Search by name…", key="explore_search")
    public = api_get("/communities", visibility="public")

    if isinstance(public, list):
        filtered = [
            c for c in public
            if not search or search.lower() in c.get("name", "").lower()
        ] if search else public

        if filtered:
            cols = st.columns(3)
            for i, c in enumerate(filtered):
                with cols[i % 3]:
                    st.markdown(
                        f'<div class="metric-card">'
                        f'<strong>{c["name"]}</strong><br>'
                        f'<small>{c.get("description","")[:80]}</small><br><br>'
                        f'👥 {c.get("member_count","?")} members &nbsp;|&nbsp; '
                        f'{c.get("join_policy","")}',
                        unsafe_allow_html=True,
                    )
                    if c.get("join_policy") == "open" and st.button("Join", key=f"join_{c['community_id']}"):
                        api_post(f"/communities/{c['community_id']}/join",
                                 {"tenant_id": tenant_id})
                        st.success("Joined!")
        else:
            st.info("No public communities found.")
    else:
        st.info("No public communities available.")

    st.divider()
    st.subheader("Global Stats")
    stats = api_get("/communities/stats")
    if stats and isinstance(stats, dict):
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total", stats.get("total", 0))
        c2.metric("Active", stats.get("active", 0))
        c3.metric("Public", stats.get("public", 0))
        c4.metric("Suspended", stats.get("suspended", 0))


# ────────────────────────────────────────────────────────────────
# Tab 3 — Members
# ────────────────────────────────────────────────────────────────
with tabs[2]:
    st.subheader("Member Management")

    my = api_get("/communities", tenant_id=tenant_id)
    comm_names = {c["community_id"]: c["name"] for c in (my if isinstance(my, list) else [])}

    sel_cid = st.selectbox(
        "Select Community",
        options=list(comm_names.keys()),
        format_func=lambda x: comm_names.get(x, x),
        key="members_sel",
    )

    if sel_cid:
        members = api_get(f"/communities/{sel_cid}/members")
        if isinstance(members, list):
            sorted_members = sorted(members, key=lambda m: m.get("joined_at", ""), reverse=True)
            st.write(f"**{len(sorted_members)} active member(s)**")

            enable_remove = st.toggle("Enable member removal", key="enable_remove")

            for m in sorted_members:
                mc1, mc2, mc3, mc4 = st.columns([3, 1, 1, 1])
                mc1.write(f"`{m['display_name'] or m['tenant_id'][:20]}` · {m['tenant_id'][:24]}…")
                mc2.write(f"**{m['role']}**")
                mc3.write(fmt_date(m.get("joined_at", "")))
                if enable_remove:
                    rm_key = f"rm_{m['member_id']}"
                    if mc4.button("Remove", key=rm_key, type="secondary"):
                        ok = api_delete(
                            f"/communities/{sel_cid}/members/{m['member_id']}"
                        )
                        if ok:
                            st_toast(f"Removed {m['display_name'] or m['tenant_id'][:16]}", "👋")
                            time.sleep(0.4)
                            st.rerun()
                        else:
                            st.error("Could not remove member.")

        st.divider()
        with st.form("add_member_form"):
            new_tid = st.text_input("Tenant ID to add")
            new_role = st.selectbox("Role", ["member", "admin", "observer"])
            new_dn = st.text_input("Display Name (optional)")
            if st.form_submit_button("Add Member"):
                res = api_post(f"/communities/{sel_cid}/members", {
                    "tenant_id": new_tid, "role": new_role, "display_name": new_dn,
                })
                if res.get("member_id"):
                    st_toast(f"Member added: {new_dn or new_tid[:16]}", "👤")
                st.rerun()


# ────────────────────────────────────────────────────────────────
# Tab 4 — Data
# ────────────────────────────────────────────────────────────────
with tabs[3]:
    st.subheader("Shared Community Data")

    my4 = api_get("/communities", tenant_id=tenant_id)
    comm_names4 = {c["community_id"]: c["name"] for c in (my4 if isinstance(my4, list) else [])}
    sel_cid4 = st.selectbox(
        "Community", options=list(comm_names4.keys()),
        format_func=lambda x: comm_names4.get(x, x), key="data_sel",
    )

    if sel_cid4:
        stats4 = api_get(f"/communities/{sel_cid4}/analytics")
        if isinstance(stats4, dict) and stats4.get("data"):
            d = stats4["data"]
            dc1, dc2, dc3 = st.columns(3)
            dc1.metric("Files", d.get("total_files", 0))
            dc2.metric("Storage", f"{d.get('total_mb', 0):.1f} MB")
            dc3.metric("Downloads", d.get("total_downloads", 0))

        files = api_get(f"/communities/{sel_cid4}/data")
        if isinstance(files, list) and files:
            import pandas as pd
            df = pd.DataFrame([{
                "Filename": f["filename"],
                "Size": f"{f['size_bytes']/1024:.1f} KB",
                "Type": f["content_type"],
                "Context": f.get("context", ""),
                "Uploaded": f["uploaded_at"][:10],
                "Downloads": f["download_count"],
                "UECIID": f.get("ueciid", "")[:14] + "…",
            } for f in files])
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No files yet.")

        st.divider()
        st.markdown("**Upload File**")
        uploaded_file = st.file_uploader(
            "Choose a file", key=f"uploader_{sel_cid4}"
        )
        ctx_text = st.text_input(
            "Context / notes (optional)",
            placeholder="e.g. Q2 threat model, internal use only",
            key=f"ctx_{sel_cid4}",
        )
        if uploaded_file and st.button("Upload →", key="upload_btn"):
            with st.spinner("Uploading…"):
                try:
                    _resp_up = httpx.post(
                        f"{BASE}/communities/{sel_cid4}/data/upload",
                        files={
                            "file": (
                                uploaded_file.name,
                                uploaded_file.getvalue(),
                                uploaded_file.type or "application/octet-stream",
                            )
                        },
                        data={"context": ctx_text},
                        params={"uploader_tenant_id": tenant_id},
                        headers=HEADERS,
                        timeout=30.0,
                    )
                    if _resp_up.status_code == 201:
                        st_toast(f"Uploaded: {uploaded_file.name}", "📁")
                        time.sleep(0.5)
                        st.rerun()
                    else:
                        st.error(f"Upload failed ({_resp_up.status_code}): {_resp_up.text[:200]}")
                except Exception as exc:
                    st.error(f"Upload error: {exc}")


# ────────────────────────────────────────────────────────────────
# Tab 5 — Compliance
# ────────────────────────────────────────────────────────────────
with tabs[4]:
    st.subheader("Community Compliance")

    my5 = api_get("/communities", tenant_id=tenant_id)
    comm_names5 = {c["community_id"]: c["name"] for c in (my5 if isinstance(my5, list) else [])}
    sel_cid5 = st.selectbox(
        "Community", options=list(comm_names5.keys()),
        format_func=lambda x: comm_names5.get(x, x), key="comp_sel",
    )

    if sel_cid5:
        comp = api_get(f"/communities/{sel_cid5}/compliance")
        if isinstance(comp, dict):
            score = comp.get("score", 0)
            status = comp.get("status", "UNKNOWN")
            sc_color = {"COMPLIANT": "normal", "PARTIAL": "off", "NON_COMPLIANT": "inverse"}
            st.metric(
                "Compliance Score",
                f"{score:.0%}",
                delta=status,
                delta_color=sc_color.get(status, "off"),  # type: ignore[arg-type]
            )

            st.markdown("### Controls")
            for ctrl in comp.get("controls", []):
                ico = {"PASS": "✅", "FAIL": "❌", "WARN": "⚠️", "SKIP": "⬜", "INFO": "ℹ️"}
                st.write(f"{ico.get(ctrl['status'], '?')} **{ctrl['control']}** — {ctrl['detail']}")

            if comp.get("gaps"):
                st.markdown("### Gaps to Address")
                for g in comp["gaps"]:
                    st.warning(f"**{g['control']}**: {g['detail']}")

            if st.button("📄 Export HTML Report"):
                _resp = httpx.post(
                    f"{BASE}/communities/{sel_cid5}/compliance/export",
                    headers=HEADERS, timeout=10.0,
                )
                if _resp.status_code == 200:
                    st.download_button(
                        "Download Report",
                        data=_resp.text,
                        file_name=f"compliance-{sel_cid5[:8]}.html",
                        mime="text/html",
                    )


# ────────────────────────────────────────────────────────────────
# Tab 6 — Evolution
# ────────────────────────────────────────────────────────────────
with tabs[5]:
    st.subheader("AI Evolution Rule Sharing")
    st.caption(
        "Share anonymised jailbreak signatures and embedding examples with "
        "federated communities. All rules require human approval before import."
    )

    my6 = api_get("/communities", tenant_id=tenant_id)
    comm_names6 = {c["community_id"]: c["name"] for c in (my6 if isinstance(my6, list) else [])}
    sel_cid6 = st.selectbox(
        "Community", options=list(comm_names6.keys()),
        format_func=lambda x: comm_names6.get(x, x), key="evo_sel",
    )

    if sel_cid6:
        evo_stats = api_get(f"/communities/{sel_cid6}/evolution/stats")
        if isinstance(evo_stats, dict):
            ec1, ec2, ec3, ec4 = st.columns(4)
            ec1.metric("Total Rules", evo_stats.get("total", 0))
            ec2.metric("Approved", evo_stats.get("approved", 0))
            ec3.metric("Pending", evo_stats.get("pending", 0))
            ec4.metric("Total Imports", evo_stats.get("total_imports", 0))

        st.divider()
        ec_left, ec_right = st.columns([1, 1])

        with ec_left:
            st.markdown("**Share a Rule**")
            with st.form("share_rule_form"):
                rule_type = st.selectbox(
                    "Rule Type",
                    ["jailbreak_signature", "embedding_example",
                     "regex_pattern", "compound_rule"],
                )
                rule_content = st.text_area("Rule Content (anonymised)", height=100)
                if st.form_submit_button("Share →"):
                    result = api_post(f"/communities/{sel_cid6}/evolution/share", {
                        "publisher_tenant_id": tenant_id,
                        "rule_type": rule_type,
                        "rule_content": rule_content,
                    })
                    if result.get("bundle_id"):
                        st.success(f"Shared: `{result['bundle_id'][:12]}…` (pending review)")
                        st.rerun()

        with ec_right:
            st.markdown("**Pending Approval**")
            pending = api_get(f"/communities/{sel_cid6}/evolution/bundles", status="pending_review")
            if isinstance(pending, list) and pending:
                for b in pending[:5]:
                    st.code(b["rule_content"][:80], language="text")
                    ba, bb = st.columns(2)
                    if ba.button("Approve", key=f"appr_{b['bundle_id']}"):
                        api_post(
                            f"/communities/{sel_cid6}/evolution/bundles/{b['bundle_id']}/approve",
                            {"reviewer_tenant_id": tenant_id},
                        )
                        st.rerun()
                    if bb.button("Reject", key=f"rjct_{b['bundle_id']}"):
                        httpx.post(
                            f"{BASE}/communities/{sel_cid6}/evolution/bundles/{b['bundle_id']}/reject",
                            headers=HEADERS, timeout=5.0,
                        )
                        st.rerun()
            else:
                st.info("No pending rules.")

        st.divider()
        st.markdown("**Approved Rules (ready to import)**")
        approved = api_get(f"/communities/{sel_cid6}/evolution/bundles", status="approved")
        if isinstance(approved, list) and approved:
            for b in approved:
                ab1, ab2, ab3 = st.columns([3, 1, 1])
                ab1.write(f"`{b['rule_type']}` — {b['rule_content'][:60]}…")
                ab2.write(f"Imports: {b['import_count']}")
                if ab3.button("Import", key=f"imp_{b['bundle_id']}"):
                    api_post(
                        f"/communities/{sel_cid6}/evolution/bundles/{b['bundle_id']}/import",
                        {},
                    )
                    st.success("Imported into local evolution engine")
        else:
            st.info("No approved rules available.")


# ────────────────────────────────────────────────────────────────
# Tab 7 — Settings
# ────────────────────────────────────────────────────────────────
with tabs[6]:
    st.subheader("Community Settings")

    my7 = api_get("/communities", tenant_id=tenant_id)
    comm_names7 = {c["community_id"]: c["name"] for c in (my7 if isinstance(my7, list) else [])}
    sel_cid7 = st.selectbox(
        "Community", options=list(comm_names7.keys()),
        format_func=lambda x: comm_names7.get(x, x), key="settings_sel",
    )

    if sel_cid7:
        comm_detail = api_get(f"/communities/{sel_cid7}")
        if not isinstance(comm_detail, dict):
            comm_detail = next(
                (c for c in my7 if c["community_id"] == sel_cid7), {}
            ) if isinstance(my7, list) else {}

        st.markdown("### General")
        with st.form("patch_community_form"):
            patch_name = st.text_input(
                "Name", value=comm_detail.get("name", "")
            )
            patch_desc = st.text_area(
                "Description", value=comm_detail.get("description", ""), height=100
            )
            if st.form_submit_button("Save Changes"):
                payload: dict = {}
                if patch_name != comm_detail.get("name"):
                    payload["name"] = patch_name
                if patch_desc != comm_detail.get("description"):
                    payload["description"] = patch_desc
                if payload:
                    r = api_patch(f"/communities/{sel_cid7}", payload)
                    if r.get("status") == "updated":
                        st.success("Community updated.")
                        st.rerun()
                else:
                    st.info("No changes to save.")

        st.markdown("### Visibility & Access")
        with st.form("settings_form"):
            vis = st.selectbox(
                "Visibility",
                ["private", "public"],
                index=["private", "public"].index(
                    comm_detail.get("visibility", "private")
                ),
            )
            pol = st.selectbox(
                "Join Policy",
                ["invite", "open", "approval"],
                index=["invite", "open", "approval"].index(
                    comm_detail.get("join_policy", "invite")
                ),
            )
            if st.form_submit_button("Update Settings"):
                api_post(f"/communities/{sel_cid7}/settings", {
                    "visibility": vis, "join_policy": pol
                })
                st.success("Settings updated.")
                st.rerun()

        st.markdown("### Danger Zone")
        st.markdown('<div class="danger-zone">', unsafe_allow_html=True)
        confirm_key7 = f"confirm_del_settings_{sel_cid7}"
        if not st.session_state.get(confirm_key7):
            if st.button("🗑️ Delete This Community", key="del_from_settings"):
                st.session_state[confirm_key7] = True
                st.rerun()
        else:
            st.warning(f"Permanently delete **{comm_detail.get('name', sel_cid7)}**?")
            ds1, ds2 = st.columns(2)
            if ds1.button("Yes, delete permanently", type="primary", key="yes_del_settings"):
                ok = api_delete(f"/communities/{sel_cid7}", requester_tenant_id=tenant_id)
                st.session_state[confirm_key7] = False
                if ok:
                    st_toast("Community deleted.", "🗑️")
                    time.sleep(0.5)
                    st.rerun()
                else:
                    st.error("Delete failed — you may not be the owner.")
            if ds2.button("Cancel", key="cancel_del_settings"):
                st.session_state[confirm_key7] = False
                st.rerun()
        st.markdown('</div>', unsafe_allow_html=True)
