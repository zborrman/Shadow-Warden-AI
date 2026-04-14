"""
Shadow Warden AI — Settings Page
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Three tabs:
  1. Threat Radar          — OSV dependency CVE scanner + ArXiv AI threat feed
  2. Intel Bridge          — Auto-Evolution sync status + manual trigger
  3. Causal Arbiter        — Interactive Bayesian DAG probability visualizer

Run with the main dashboard:
    streamlit run warden/analytics/dashboard.py
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import plotly.graph_objects as go
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from warden.analytics.auth import require_auth
from warden.intel_ops import WardenIntelOps

# ── Auth ──────────────────────────────────────────────────────────────────────
require_auth()

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Shadow Warden AI — Settings",
    page_icon="⚙️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Dark-mode CSS (mirrors dashboard.py) ─────────────────────────────────────
st.markdown("""
<style>
  .metric-card {
    background: #1a1f2e; border: 1px solid #2d3748;
    border-radius: 10px; padding: 18px 22px; text-align: center;
  }
  .metric-value { font-size: 2rem; font-weight: 700; color: #e2e8f0; }
  .metric-label { font-size: 0.82rem; color: #718096; letter-spacing: .05em; }
  .section-title {
    font-size: 1.05rem; font-weight: 600; color: #a0aec0;
    margin: 1rem 0 .4rem; letter-spacing: .08em; text-transform: uppercase;
  }
  .cve-critical { color: #fc4444; font-weight: 700; }
  .cve-high     { color: #fc8181; font-weight: 600; }
  .cve-medium   { color: #f6ad55; }
  .cve-low      { color: #68d391; }
  .cve-unknown  { color: #a0aec0; }
</style>
""", unsafe_allow_html=True)

st.title("⚙️ Settings & Threat Intelligence")

tab_radar, tab_bridge, tab_arbiter = st.tabs([
    "🔍 Threat Radar",
    "🔗 Intel Bridge",
    "🧠 Causal Arbiter",
])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — THREAT RADAR
# ══════════════════════════════════════════════════════════════════════════════

with tab_radar:
    st.markdown('<p class="section-title">Dependency CVE Scanner + ArXiv AI Threat Feed</p>',
                unsafe_allow_html=True)

    col_scan, col_status = st.columns([1, 3])
    with col_scan:
        run_scan = st.button("▶ Run Full Scan", use_container_width=True, type="primary")

    # Load last report
    report = WardenIntelOps.load_report()

    if run_scan:
        with st.spinner("Scanning dependencies and hunting ArXiv threats …"):
            try:
                ops = WardenIntelOps()
                alerts = asyncio.run(ops.run_audit())
                report = WardenIntelOps.load_report()
                st.success(f"Scan complete — {len(alerts)} alert(s) found.")
            except Exception as exc:
                st.error(f"Scan error: {exc}")

    if report:
        scanned_at = report.get("scanned_at", "unknown")
        cve_count   = report.get("cve_count", 0)
        intel_count = report.get("intel_count", 0)
        alerts      = report.get("alerts", [])

        with col_status:
            st.caption(f"Last scan: **{scanned_at}**")

        # ── Metrics row ───────────────────────────────────────────────
        m1, m2, m3 = st.columns(3)
        with m1:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-value">{cve_count}</div>'
                f'<div class="metric-label">CVEs Found</div></div>',
                unsafe_allow_html=True,
            )
        with m2:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-value">{intel_count}</div>'
                f'<div class="metric-label">ArXiv Papers</div></div>',
                unsafe_allow_html=True,
            )
        crit = sum(1 for a in alerts if a.get("severity") == "CRITICAL")
        with m3:
            st.markdown(
                f'<div class="metric-card">'
                f'<div class="metric-value cve-critical">{crit}</div>'
                f'<div class="metric-label">Critical CVEs</div></div>',
                unsafe_allow_html=True,
            )

        st.divider()

        # ── CVE Table ─────────────────────────────────────────────────
        cves = [a for a in alerts if a["type"] == "dependency_cve"]
        if cves:
            st.markdown('<p class="section-title">Dependency Vulnerabilities</p>',
                        unsafe_allow_html=True)
            _sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
            cves_sorted = sorted(cves, key=lambda x: _sev_order.get(x.get("severity", "UNKNOWN"), 4))

            for cve in cves_sorted:
                sev = cve.get("severity", "UNKNOWN").lower()
                link = cve.get("link", "#")
                st.markdown(
                    f'<span class="cve-{sev}">⚠ [{cve["cve"]}]({link})</span> &nbsp; '
                    f'**{cve["package"]}** `{cve["version"]}` — {cve["details"][:120]}',
                    unsafe_allow_html=True,
                )
        else:
            st.success("✅ No dependency CVEs detected.")

        st.divider()

        # ── ArXiv Papers ──────────────────────────────────────────────
        papers = [a for a in alerts if a["type"] == "new_threat_intel"]
        if papers:
            st.markdown('<p class="section-title">AI Threat Research (ArXiv)</p>',
                        unsafe_allow_html=True)
            for paper in papers:
                pub = paper.get("published", "")[:10]
                with st.expander(f"📄 {paper['title']}", expanded=False):
                    st.markdown(f"**Published:** {pub}")
                    st.markdown(f"**Source:** {paper['source']}")
                    if paper.get("summary"):
                        st.markdown(paper["summary"])
                    st.markdown(f"[Open on ArXiv ↗]({paper['link']})")
        else:
            st.info("No ArXiv papers loaded. Run a scan to fetch the latest research.")
    else:
        st.info("No scan results yet. Click **Run Full Scan** to begin.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — INTEL BRIDGE
# ══════════════════════════════════════════════════════════════════════════════

with tab_bridge:
    st.markdown('<p class="section-title">Auto-Evolution Bridge — ArXiv → Claude Opus → SemanticGuard</p>',
                unsafe_allow_html=True)

    st.markdown("""
    The **Intel Bridge** reads ArXiv research papers found by the Threat Radar and
    asks **Claude Opus** to synthesise concrete attack prompt examples from each paper.
    Those examples are hot-loaded into the SemanticGuard corpus — no restart required.

    | Step | Component | Action |
    |------|-----------|--------|
    | 1 | WardenIntelOps | Fetch ArXiv papers matching LLM-attack queries |
    | 2 | EvolutionEngine | `synthesize_from_intel()` → Claude Opus → 5 examples/paper |
    | 3 | SemanticGuard | `add_examples()` → Poincaré corpus hot-reload |

    **Env vars:** `INTEL_OPS_ENABLED=true` · `INTEL_BRIDGE_INTERVAL_HRS=6` · `ANTHROPIC_API_KEY`
    """)

    st.divider()

    col_sync, col_info = st.columns([1, 2])
    with col_sync:
        manual_sync = st.button("⚡ Sync Now (one-shot)", use_container_width=True, type="primary")

    if manual_sync:
        with st.spinner("Running threat synchronization cycle …"):
            try:
                import warden.main as _main
                bridge = getattr(_main, "_intel_bridge", None)
                if bridge is not None:
                    loop = asyncio.new_event_loop()
                    summary = loop.run_until_complete(bridge.synchronize_threats())
                    loop.close()
                    st.success(
                        f"Sync complete — {summary['papers_new']} new paper(s), "
                        f"{summary['examples_added']} example(s) added to corpus."
                    )
                    st.json(summary)
                else:
                    # Not wired into main (standalone dashboard) — run directly
                    from warden.intel_ops import WardenIntelOps
                    ops = WardenIntelOps()
                    loop = asyncio.new_event_loop()
                    alerts = loop.run_until_complete(ops.run_audit())
                    loop.close()
                    intel = [a for a in alerts if a["type"] == "new_threat_intel"]
                    st.success(
                        f"Intel-only sync done — {len(intel)} paper(s) found. "
                        "Evolution Engine not active (set INTEL_OPS_ENABLED=true + ANTHROPIC_API_KEY)."
                    )
            except Exception as exc:
                st.error(f"Sync error: {exc}")

    with col_info:
        st.caption(
            "Note: synthesis requires **ANTHROPIC_API_KEY** and "
            "**INTEL_OPS_ENABLED=true** in the environment."
        )

    # Show last report intel items as a quick reference
    report = WardenIntelOps.load_report()
    if report:
        papers = [a for a in report.get("alerts", []) if a["type"] == "new_threat_intel"]
        if papers:
            st.markdown(f"**{len(papers)} paper(s) available in last scan** "
                        f"(scanned: {report.get('scanned_at', '?')[:19]})")
            for p in papers[:5]:
                st.markdown(f"- [{p['title'][:90]}]({p['link']})")
            if len(papers) > 5:
                st.caption(f"… and {len(papers) - 5} more. Run Threat Radar for full list.")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — CAUSAL ARBITER VISUALIZER
# ══════════════════════════════════════════════════════════════════════════════

with tab_arbiter:
    st.markdown('<p class="section-title">Causal Arbiter — Interactive Bayesian DAG Simulator</p>',
                unsafe_allow_html=True)
    st.markdown(
        "Adjust the input signals below and see in real-time how the 6-node "
        "Bayesian causal DAG computes **P(HIGH_RISK | evidence)**."
    )

    # ── Input sliders ─────────────────────────────────────────────────────────
    col_inputs, col_viz = st.columns([1, 2], gap="large")

    with col_inputs:
        st.markdown("**Input Signals**")

        ml_score = st.slider(
            "ML Similarity Score", 0.0, 1.0, 0.45, 0.01,
            help="SemanticBrain cosine/hyperbolic similarity (0=safe, 1=certain attack)",
        )
        ers_score = st.slider(
            "Entity Risk Score (ERS)", 0.0, 1.0, 0.20, 0.01,
            help="Sliding-window reputation score for this entity (0=clean, 1=known bad)",
        )
        obfuscation = st.checkbox(
            "Obfuscation Detected",
            value=False,
            help="True if base64/hex/ROT13/homoglyph decoding was triggered",
        )
        block_history = st.slider(
            "Block History (session)", 0, 20, 0, 1,
            help="Number of times this session has been blocked",
        )
        tool_tier = st.select_slider(
            "Tool Tier",
            options=[-1, 0, 1, 2],
            value=0,
            format_func={-1: "-1 (unknown)", 0: "0 (read)", 1: "1 (write)", 2: "2 (destructive)"}.__getitem__,
            help="Privilege level of the AI tool being invoked",
        )
        content_entropy = st.slider(
            "Content Entropy (bits/char)", 2.0, 7.0, 4.2, 0.1,
            help="Shannon entropy. Natural language ≈ 3.8–4.8. High values signal obfuscation.",
        )
        se_risk = st.slider(
            "SE-Arbiter Risk (social engineering)", 0.0, 1.0, 0.0, 0.01,
            help="P(SE_RISK) from PhishGuard SE-Arbiter (0=no SE signal detected)",
        )

    # ── Compute ───────────────────────────────────────────────────────────────
    try:
        from warden.causal_arbiter import arbitrate
        result = arbitrate(
            ml_score             = ml_score,
            ers_score            = ers_score,
            obfuscation_detected = obfuscation,
            block_history        = block_history,
            tool_tier            = tool_tier,
            content_entropy      = content_entropy,
            se_risk              = se_risk,
        )
        arb_ok = True
    except Exception as arb_exc:
        arb_ok = False
        arb_error = str(arb_exc)

    with col_viz:
        if not arb_ok:
            st.error(f"Causal Arbiter error: {arb_error}")
        else:
            # ── Decision badge ────────────────────────────────────────
            risk_pct = result.risk_probability * 100
            if result.is_high_risk:
                badge_color, badge_label = "#fc4444", "HIGH RISK — BLOCK"
            elif risk_pct >= 40:
                badge_color, badge_label = "#f6ad55", "ELEVATED — REVIEW"
            else:
                badge_color, badge_label = "#48bb78", "ALLOWED"

            st.markdown(
                f'<div style="background:{badge_color}22; border:2px solid {badge_color}; '
                f'border-radius:10px; padding:16px 24px; text-align:center; margin-bottom:16px;">'
                f'<span style="font-size:1.6rem; font-weight:700; color:{badge_color};">'
                f'{badge_label}</span><br>'
                f'<span style="color:#e2e8f0; font-size:1.1rem;">'
                f'P(HIGH_RISK) = <b>{risk_pct:.1f}%</b></span></div>',
                unsafe_allow_html=True,
            )

            # ── Node contribution waterfall ───────────────────────────
            nodes = [
                ("Reputation\n(ERS)",         result.p_reputation),
                ("Content Risk\n(Obfusc)",    result.p_content_risk),
                ("Persistence\n(Blocks)",     result.p_persistence),
                ("Tool Risk\n(Tier)",         result.p_tool_risk),
                ("Entropy Risk\n(Content)",   result.p_entropy_risk),
                ("SE Risk\n(PhishGuard)",     result.p_se_risk),
            ]
            labels = [n[0] for n in nodes]
            values = [round(n[1] * 100, 1) for n in nodes]

            colors = [
                "#fc4444" if v >= 70 else
                "#f6ad55" if v >= 40 else
                "#48bb78"
                for v in values
            ]

            fig_bar = go.Figure(go.Bar(
                x=labels,
                y=values,
                marker_color=colors,
                text=[f"{v:.0f}%" for v in values],
                textposition="outside",
            ))
            fig_bar.update_layout(
                title="Causal Node Probabilities",
                yaxis={"range": [0, 110], "title": "Probability (%)", "gridcolor": "#2d3748"},
                xaxis={"gridcolor": "#2d3748"},
                paper_bgcolor="#111827",
                plot_bgcolor="#111827",
                font={"color": "#e2e8f0"},
                height=300,
                margin={"l": 10, "r": 10, "t": 40, "b": 10},
            )
            st.plotly_chart(fig_bar, use_container_width=True)

            # ── Gauge ─────────────────────────────────────────────────
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number+delta",
                value=risk_pct,
                delta={"reference": 65.0, "valueformat": ".1f"},
                number={"suffix": "%", "font": {"size": 36}},
                gauge={
                    "axis": {"range": [0, 100], "tickwidth": 1, "tickcolor": "#718096"},
                    "bar": {"color": badge_color},
                    "bgcolor": "#1a1f2e",
                    "bordercolor": "#2d3748",
                    "steps": [
                        {"range": [0,  40], "color": "#1a3a2a"},
                        {"range": [40, 65], "color": "#3a2e1a"},
                        {"range": [65, 100], "color": "#3a1a1a"},
                    ],
                    "threshold": {
                        "line": {"color": "#fc4444", "width": 3},
                        "thickness": 0.75,
                        "value": 65,
                    },
                },
                title={"text": "P(HIGH_RISK | evidence)", "font": {"color": "#a0aec0"}},
            ))
            fig_gauge.update_layout(
                paper_bgcolor="#111827",
                font={"color": "#e2e8f0"},
                height=260,
                margin={"l": 20, "r": 20, "t": 40, "b": 10},
            )
            st.plotly_chart(fig_gauge, use_container_width=True)

            # ── Structural equation breakdown ─────────────────────────
            with st.expander("📐 Structural Causal Equation", expanded=False):
                st.markdown(f"""
```
P(HIGH_RISK | do(signals)) =
  w_reputation  × p_reputation   = ? × {result.p_reputation:.3f}
+ w_content     × p_content_risk = ? × {result.p_content_risk:.3f}
+ w_persistence × p_persistence  = ? × {result.p_persistence:.3f}
+ w_tool        × p_tool_risk    = ? × {result.p_tool_risk:.3f}
+ w_ml          × ml_score       = ? × {ml_score:.3f}
+ w_entropy     × p_entropy_risk = ? × {result.p_entropy_risk:.3f}
+ w_se          × p_se_risk      = ? × {result.p_se_risk:.3f}
─────────────────────────────────────────────
= sigmoid( causal_score ) → {risk_pct:.1f}%

Threshold: 65% → {"BLOCK ✗" if result.is_high_risk else "ALLOW ✓"}
```
                """)
                st.caption(
                    "Weights (w_*) are calibrated from live log data via "
                    "`CausalArbiter.calibrate_from_logs()` and stored in the CPT singleton. "
                    "The exact values are intentionally omitted here to prevent threshold gaming."
                )
