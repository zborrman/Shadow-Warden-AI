"""
warden/analytics/pages/23_Marketplace_Admin.py
─────────────────────────────────────────────────
Streamlit admin page for the Community M2M Agentic Marketplace.

Tabs
────
  Agent Registry  — all registered marketplace agents
  Assets          — tokenized rules / models / signals
  Trust Graph     — TrustRank visualisation (networkx + plotly)
  Sybil Flags     — flagged agents with reasons
"""
import json
import os

import streamlit as st

from warden.db.connect import open_db_readonly

st.set_page_config(page_title="Marketplace Admin", page_icon="🏪", layout="wide")
st.title("🏪 M2M Agentic Marketplace")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")


def _conn():
    return open_db_readonly(_DB_PATH)


def _agents():
    try:
        with _conn() as con:
            rows = con.execute(
                "SELECT agent_id, community_id, tenant_id, capabilities, status, mandate_id, created_at"
                " FROM marketplace_agents ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _assets():
    try:
        with _conn() as con:
            rows = con.execute(
                "SELECT asset_id, asset_type, ipfs_hash, seller_agent_id, community_id, created_at"
                " FROM marketplace_assets ORDER BY created_at DESC LIMIT 200"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _purchases():
    try:
        with _conn() as con:
            rows = con.execute(
                "SELECT buyer_agent, seller_agent, status FROM marketplace_purchases LIMIT 2000"
            ).fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []


tab_agents, tab_assets, tab_trust, tab_sybil, tab_gov, tab_escrow, tab_maestro = st.tabs(
    ["Agent Registry", "Assets", "Trust Graph", "Sybil Flags", "Governance", "Escrow Monitor", "MAESTRO Threats"]
)

# ── Agent Registry ─────────────────────────────────────────────────────────
with tab_agents:
    agents = _agents()
    st.metric("Total Agents", len(agents))
    if not agents:
        st.info("No marketplace agents registered yet.")
    else:
        import pandas as pd
        df = pd.DataFrame(agents)
        df["agent_id_short"] = df["agent_id"].str[len("did:shadow:"):][:8] + "…"
        df["capabilities"] = df["capabilities"].apply(
            lambda v: ", ".join(json.loads(v)) if isinstance(v, str) else str(v)
        )
        st.dataframe(
            df[["agent_id_short", "community_id", "tenant_id", "capabilities", "status", "mandate_id", "created_at"]],
            use_container_width=True,
        )

# ── Assets ─────────────────────────────────────────────────────────────────
with tab_assets:
    assets = _assets()
    col1, col2, col3 = st.columns(3)
    type_counts: dict[str, int] = {}
    for a in assets:
        type_counts[a["asset_type"]] = type_counts.get(a["asset_type"], 0) + 1
    col1.metric("Rules",   type_counts.get("rule",    0))
    col2.metric("Models",  type_counts.get("model",   0))
    col3.metric("Signals", type_counts.get("signals", 0))
    if not assets:
        st.info("No marketplace assets registered yet.")
    else:
        import pandas as pd
        df = pd.DataFrame(assets)
        df["asset_id_short"] = df["asset_id"].str[:14] + "…"
        df["ipfs_short"] = df["ipfs_hash"].str[:12] + "…"
        st.dataframe(
            df[["asset_id_short", "asset_type", "seller_agent_id", "community_id", "ipfs_short", "created_at"]],
            use_container_width=True,
        )

# ── Trust Graph ─────────────────────────────────────────────────────────────
with tab_trust:
    st.subheader("Agent Trust Graph (TrustRank)")
    purchases = _purchases()
    if not purchases:
        st.info("No trade history — trust graph is empty.")
    else:
        try:
            from warden.marketplace.trust_graph import TrustGraph
            tg = TrustGraph()
            tg.build_graph()
            ranks = tg.compute_pagerank()

            # Top agents table
            top = tg.top_agents(n=20)
            if top:
                import pandas as pd
                df_rank = pd.DataFrame(top)
                df_rank["trust_rank"] = df_rank["trust_rank"].round(4)
                df_rank["agent_id_short"] = df_rank["agent_id"].str[:20] + "…"
                st.write("**Top Agents by TrustRank**")
                st.dataframe(
                    df_rank[["agent_id_short", "trust_rank"]].rename(
                        columns={"agent_id_short": "Agent", "trust_rank": "TrustRank"}
                    ),
                    use_container_width=True,
                )

            # Interactive graph via plotly (optional)
            try:
                import networkx as nx
                import plotly.graph_objects as go

                G = nx.DiGraph()
                for p in purchases:
                    b, s, st_ = p["buyer_agent"], p["seller_agent"], p["status"]
                    if b and s and b != s:
                        w = 1.0 if st_ == "completed" else (0.3 if st_ == "disputed" else 0.5)
                        G.add_edge(b, s, weight=w)

                if len(G.nodes) > 0:
                    pos = nx.spring_layout(G, seed=42)
                    max_r = max(ranks.values()) if ranks else 1.0

                    edge_x, edge_y = [], []
                    for u, v in G.edges():
                        x0, y0 = pos[u]
                        x1, y1 = pos[v]
                        edge_x += [x0, x1, None]
                        edge_y += [y0, y1, None]

                    node_x = [pos[n][0] for n in G.nodes()]
                    node_y = [pos[n][1] for n in G.nodes()]
                    node_s = [max(8, int(ranks.get(n, 0) / max(max_r, 1e-9) * 30)) for n in G.nodes()]
                    node_t = [n[:14] + "…" if len(n) > 14 else n for n in G.nodes()]

                    fig = go.Figure()
                    fig.add_trace(go.Scatter(
                        x=edge_x, y=edge_y, mode="lines",
                        line={"width": 0.5, "color": "#4b5563"}, hoverinfo="none",
                    ))
                    fig.add_trace(go.Scatter(
                        x=node_x, y=node_y, mode="markers+text",
                        marker={"size": node_s, "color": "#3b82f6", "line": {"width": 1, "color": "#1e3a5f"}},
                        text=node_t, textposition="top center",
                        hovertext=[f"{n}<br>TrustRank: {ranks.get(n, 0):.4f}" for n in G.nodes()],
                        hoverinfo="text",
                    ))
                    fig.update_layout(
                        showlegend=False, height=500,
                        margin={"l": 0, "r": 0, "t": 20, "b": 0},
                        paper_bgcolor="#0f172a", plot_bgcolor="#0f172a",
                        font={"color": "#e2e8f0"},
                        xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
                        yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
                    )
                    st.plotly_chart(fig, use_container_width=True)
            except ImportError:
                st.info("Install plotly and networkx for the interactive graph view.")
        except Exception as exc:
            st.error(f"Trust graph error: {exc}")

# ── Sybil Flags ─────────────────────────────────────────────────────────────
with tab_sybil:
    st.subheader("Sybil Flags")
    try:
        from warden.marketplace.sybil_guard import SybilGuard
        sg = SybilGuard()

        # Show in-memory flags
        flags = sg.list_flagged()
        if not flags:
            # Also try scanning all known agents
            all_agents = _agents()
            flags = []
            for ag in all_agents:
                aid = ag["agent_id"]
                if sg.is_flagged(aid):
                    flags.append({
                        "agent_id":  aid,
                        "reason":    sg.get_flag_reason(aid),
                        "flagged_at": "",
                    })

        if not flags:
            st.success("No Sybil flags active.")
        else:
            import pandas as pd
            st.metric("Flagged Agents", len(flags))
            df_flags = pd.DataFrame(flags)
            df_flags["agent_short"] = df_flags["agent_id"].str[:20] + "…"
            st.dataframe(
                df_flags[["agent_short", "reason", "flagged_at"]].rename(
                    columns={"agent_short": "Agent", "reason": "Reason", "flagged_at": "Flagged At"}
                ),
                use_container_width=True,
            )

        # Circular trade detection
        st.markdown("---")
        st.write("**Circular Trade Detector**")
        circles = sg.detect_circular_trades()
        if circles:
            import pandas as pd
            st.warning(f"{len(circles)} circular trade pair(s) detected in the last 24 h.")
            st.dataframe(
                pd.DataFrame(circles, columns=["Agent A", "Agent B"]),
                use_container_width=True,
            )
        else:
            st.success("No circular trades detected in the last 24 h.")
    except Exception as exc:
        st.error(f"Sybil guard error: {exc}")

# ── Governance ──────────────────────────────────────────────────────────────
with tab_gov:
    st.subheader("Community DAO Governance")

    _gov_community = st.text_input("Community ID", value="", key="gov_community")
    _gov_status    = st.selectbox(
        "Filter by Status",
        options=["all", "active", "passed", "rejected", "executed", "expired"],
        key="gov_status",
    )

    def _proposals(community_id: str, status: str) -> list[dict]:
        try:
            from warden.marketplace.governance import GovernanceService
            svc = GovernanceService()
            props = svc.get_proposals(
                community_id=community_id,
                status_filter=None if status == "all" else status,
                limit=100,
            )
            result = []
            for p in props:
                tally = svc.tally_votes(p.proposal_id)
                d = p.to_dict()
                d["total_voters"] = tally.get("total_voters", 0)
                d["quorum_met"] = tally.get("quorum_met", False)
                d["tally_status"] = tally.get("status", "pending")
                total_w = sum((tally.get("totals") or {}).values())
                d["vote_weight_total"] = round(total_w, 1)
                result.append(d)
            return result
        except Exception as exc:
            st.error(f"Governance error: {exc}")
            return []

    proposals = _proposals(_gov_community, _gov_status)

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Proposals", len(proposals))
    c2.metric("Active",  sum(1 for p in proposals if p["status"] == "active"))
    c3.metric("Executed", sum(1 for p in proposals if p["status"] == "executed"))

    if proposals:
        import pandas as pd
        df_gov = pd.DataFrame(proposals)
        cols = ["proposal_id", "proposal_type", "title", "status", "tally_status",
                "total_voters", "quorum_met", "vote_weight_total", "created_at"]
        st.dataframe(
            df_gov[[c for c in cols if c in df_gov.columns]],
            use_container_width=True,
        )
    else:
        st.info("No proposals found. Enter a Community ID above to load proposals.")

    st.markdown("---")

    # Create Proposal form
    with st.expander("Create New Proposal"):  # noqa: SIM117
        with st.form("create_proposal"):
            f_community = st.text_input("Community ID*")
            f_proposer  = st.text_input("Proposer ID*")
            f_type      = st.selectbox("Type", ["dispute_resolution", "parameter_change", "agent_block"])
            f_target    = st.text_input("Target ID (escrow / param / agent)")
            f_title     = st.text_input("Title*")
            f_desc      = st.text_area("Description")
            submitted = st.form_submit_button("Create Proposal")
            if submitted:
                if not f_community or not f_proposer or not f_title:
                    st.error("Community ID, Proposer ID, and Title are required.")
                else:
                    try:
                        from warden.marketplace.governance import GovernanceService
                        p = GovernanceService().create_proposal(
                            community_id=f_community,
                            proposer_id=f_proposer,
                            proposal_type=f_type,
                            target_id=f_target,
                            title=f_title,
                            description=f_desc,
                        )
                        st.success(f"Proposal created: {p.proposal_id}")
                    except Exception as exc:
                        st.error(f"Error: {exc}")

    # Vote form
    with st.expander("Cast Vote"):  # noqa: SIM117
        with st.form("cast_vote"):
            v_proposal = st.text_input("Proposal ID*")
            v_voter    = st.text_input("Voter (Agent) ID*")
            v_choice   = st.number_input("Choice (0 = first option, 1 = second, …)", min_value=0, value=0)
            v_submit   = st.form_submit_button("Cast Vote")
            if v_submit:
                if not v_proposal or not v_voter:
                    st.error("Proposal ID and Voter ID are required.")
                else:
                    try:
                        from warden.marketplace.governance import GovernanceService
                        vote = GovernanceService().cast_vote(
                            proposal_id=v_proposal,
                            voter_id=v_voter,
                            choice=int(v_choice),
                        )
                        st.success(f"Vote cast: {vote.vote_id} (weight={vote.weight:.1f})")
                    except Exception as exc:
                        st.error(f"Error: {exc}")

    # Execute button
    with st.expander("Execute Passed Proposal"), st.form("execute_proposal"):
        e_proposal = st.text_input("Proposal ID*")
        e_submit   = st.form_submit_button("Execute")
        if e_submit:
            if not e_proposal:
                st.error("Proposal ID is required.")
            else:
                try:
                    from warden.marketplace.governance import GovernanceService
                    svc = GovernanceService()
                    svc.finalize_tally(e_proposal)
                    result = svc.execute_proposal(e_proposal)
                    st.success(f"Executed: action={result.get('action')}")
                    st.json(result)
                except Exception as exc:
                    st.error(f"Error: {exc}")

# ── Escrow Monitor ──────────────────────────────────────────────────────────
with tab_escrow:
    st.subheader("Escrow Monitor")

    def _escrows(status_filter: str | None, chain_filter: str | None) -> list[dict]:
        try:
            with _conn() as con:
                if status_filter and chain_filter:
                    rows = con.execute(
                        "SELECT * FROM marketplace_escrow WHERE status=? AND chain=?"
                        " ORDER BY created_at DESC LIMIT 200",
                        (status_filter, chain_filter),
                    ).fetchall()
                elif status_filter:
                    rows = con.execute(
                        "SELECT * FROM marketplace_escrow WHERE status=?"
                        " ORDER BY created_at DESC LIMIT 200",
                        (status_filter,),
                    ).fetchall()
                elif chain_filter:
                    rows = con.execute(
                        "SELECT * FROM marketplace_escrow WHERE chain=?"
                        " ORDER BY created_at DESC LIMIT 200",
                        (chain_filter,),
                    ).fetchall()
                else:
                    rows = con.execute(
                        "SELECT * FROM marketplace_escrow ORDER BY created_at DESC LIMIT 200"
                    ).fetchall()
            return [dict(r) for r in rows]
        except Exception:
            return []

    col_cf, col_sf = st.columns(2)
    _chain_opt = col_cf.selectbox(
        "Chain",
        options=["all", "sepolia", "polygon_amoy", "arbitrum_sepolia"],
        key="escrow_chain",
    )
    _status_opt = col_sf.selectbox(
        "Status",
        options=["all", "pending_deposit", "funded", "delivered", "confirmed",
                 "disputed", "resolved_buyer", "resolved_seller", "cancelled"],
        key="escrow_status",
    )

    escrows = _escrows(
        None if _status_opt == "all" else _status_opt,
        None if _chain_opt == "all" else _chain_opt,
    )

    ec1, ec2, ec3, ec4 = st.columns(4)
    ec1.metric("Total", len(escrows))
    ec2.metric("Active", sum(1 for e in escrows if e.get("status") in ("funded", "delivered")))
    ec3.metric("Disputed", sum(1 for e in escrows if e.get("status") == "disputed"))
    ec4.metric("Confirmed", sum(1 for e in escrows if e.get("status") == "confirmed"))

    if not escrows:
        st.info("No escrow records match the selected filters.")
    else:
        import pandas as pd
        df_esc = pd.DataFrame(escrows)
        display_cols = [c for c in [
            "escrow_id", "chain", "status", "amount_usd",
            "buyer_agent", "seller_agent", "created_at",
        ] if c in df_esc.columns]
        df_esc["escrow_id"] = df_esc["escrow_id"].str[:18] + "…"
        df_esc["buyer_agent"] = df_esc["buyer_agent"].str[:16] + "…"
        df_esc["seller_agent"] = df_esc["seller_agent"].str[:16] + "…"
        st.dataframe(df_esc[display_cols], use_container_width=True)

        # Chain distribution
        if "chain" in df_esc.columns:
            chain_counts = df_esc["chain"].value_counts().reset_index()
            chain_counts.columns = ["chain", "count"]
            st.write("**Chain Distribution**")
            st.bar_chart(chain_counts.set_index("chain")["count"])

# ── MAESTRO Threats ──────────────────────────────────────────────────────────
with tab_maestro:
    st.subheader("MAESTRO Threat Detection")
    st.markdown(
        "Monitors M2M marketplace agents for **goal misalignment**, **collusion**, "
        "and **model poisoning**. Penalty propagates to ReputationEngine (10% weight)."
    )

    col_run, _col_spacer = st.columns([2, 1])
    with col_run:
        audit_agent = st.text_input(
            "Run Full Audit for Agent ID",
            placeholder="AGENT-abc123…",
            key="maestro_audit_agent_id",
        )
    run_audit = st.button("Run Audit", type="primary", key="maestro_run_btn")

    if run_audit and audit_agent.strip():
        with st.spinner("Running MAESTRO audit…"):
            try:
                from warden.marketplace.maestro import get_maestro_service as _gms
                _msvc = _gms(_DB_PATH)
                report = _msvc.run_full_audit(audit_agent.strip())
                r = report.to_dict()
                level_color = {"low": "green", "medium": "orange", "high": "red"}.get(
                    r["overall_threat_level"], "gray"
                )
                st.markdown(
                    f"**Threat Level:** :{level_color}[{r['overall_threat_level'].upper()}]"
                    f"  |  **Action:** `{r['recommended_action']}`"
                )
                c1, c2, c3 = st.columns(3)
                c1.metric("Misalignment Score", f"{r['misalignment_score']:.3f}")
                c2.metric("Collusion Flags", len(r["collusion_flags"]))
                c3.metric("Poisoning Risk", "Yes" if r["poisoning_risk"] else "No")
                if r["collusion_flags"]:
                    st.warning(f"Collusion partners: {', '.join(r['collusion_flags'])}")
            except Exception as exc:
                st.error(f"Audit failed: {exc}")

    st.divider()
    st.subheader("All Active MAESTRO Flags")

    m_limit = st.slider("Max flags", 10, 500, 100, step=10, key="maestro_flags_limit")
    try:
        from warden.marketplace.maestro import get_maestro_service as _gms2
        _msvc2 = _gms2(_DB_PATH)
        m_flags = _msvc2.list_flagged_agents(limit=m_limit)
        if not m_flags:
            st.success("No MAESTRO flags recorded yet.")
        else:
            import pandas as pd
            df_mf = pd.DataFrame(m_flags)
            if "created_at" in df_mf.columns:
                df_mf["created_at"] = pd.to_datetime(df_mf["created_at"], errors="coerce")
            if "flag_type" in df_mf.columns:
                ftype_counts = df_mf["flag_type"].value_counts().to_dict()
                st.markdown(" · ".join(f"**{k}**: {v}" for k, v in ftype_counts.items()))
            st.dataframe(df_mf, use_container_width=True, hide_index=True)

            # Historical chart for most-flagged agent
            if "agent_id" in df_mf.columns and not df_mf.empty:
                top_agent = df_mf["agent_id"].value_counts().idxmax()
                history = _msvc2.get_historical_scores(top_agent)
                if len(history) >= 2:
                    st.subheader(f"Misalignment History — {top_agent[:20]}…")
                    hist_df = pd.DataFrame(history)
                    hist_df["ts"] = pd.to_datetime(hist_df["ts"], errors="coerce")
                    hist_df = hist_df.set_index("ts")
                    st.line_chart(hist_df["score"])
    except Exception as exc:
        st.error(f"Could not load MAESTRO flags: {exc}")
