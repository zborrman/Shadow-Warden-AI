"""
warden/xai/renderer.py
──────────────────────
XAI report renderers — HTML (primary) and PDF (optional via reportlab).

HTML renderer
─────────────
Produces a self-contained, print-ready HTML page with:
  • Risk gauge (SVG arc)
  • Pipeline flow diagram (stage cards + arrows)
  • Stage detail cards (collapsible)
  • Counterfactual remediation table
  • Raw JSON payload (collapsible)

PDF renderer
────────────
If reportlab is installed, `render_pdf(chain)` generates a professional
multi-page PDF.  Falls back to `{"format":"html", "content": <html_bytes>}`
with an HTTP header hint when reportlab is unavailable.

Both renderers accept a `CausalChain` and return bytes.
"""
from __future__ import annotations

import html as _html
import json
from datetime import UTC, datetime

from warden.xai.chain import CausalChain, chain_to_dict

# ── Verdict styling ────────────────────────────────────────────────────────────

_VERDICT_CSS: dict[str, str] = {
    "BLOCK": "background:#fee2e2;border-left:4px solid #ef4444;color:#7f1d1d",
    "FLAG":  "background:#fef3c7;border-left:4px solid #f59e0b;color:#78350f",
    "PASS":  "background:#dcfce7;border-left:4px solid #22c55e;color:#14532d",
    "SKIP":  "background:#f1f5f9;border-left:4px solid #94a3b8;color:#475569",
}

_RISK_COLOR: dict[str, str] = {
    "CRITICAL": "#dc2626",
    "HIGH":     "#ef4444",
    "MEDIUM":   "#f59e0b",
    "LOW":      "#22c55e",
    "UNKNOWN":  "#94a3b8",
}


# ── HTML renderer ─────────────────────────────────────────────────────────────

def render_html(chain: CausalChain) -> bytes:
    """Render *chain* as a self-contained UTF-8 HTML report."""
    risk_color  = _RISK_COLOR.get(chain.risk_level, "#94a3b8")
    verdict_bg  = "#fee2e2" if chain.final_verdict == "BLOCKED" else "#dcfce7"
    verdict_col = "#7f1d1d" if chain.final_verdict == "BLOCKED" else "#14532d"
    ts_fmt      = chain.timestamp[:19].replace("T", " ") + " UTC" if chain.timestamp else "unknown"
    chain_json  = _html.escape(json.dumps(chain_to_dict(chain), indent=2))

    nodes_html  = _render_nodes(chain)
    cf_html     = _render_counterfactuals(chain)

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Shadow Warden — XAI Report · {_h(chain.request_id[:16])}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
      background:#f8fafc;color:#0f172a;line-height:1.5;font-size:14px}}
.page{{max-width:960px;margin:0 auto;padding:32px 24px}}
h1{{font-size:22px;font-weight:700;color:#1e293b}}
h2{{font-size:15px;font-weight:600;color:#334155;margin-bottom:12px;
    padding-bottom:6px;border-bottom:1px solid #e2e8f0}}
.badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600}}
.header{{display:flex;justify-content:space-between;align-items:flex-start;
         background:#fff;border-radius:12px;padding:20px 24px;
         box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px}}
.header-meta{{color:#64748b;font-size:12px;line-height:2}}
.verdict-pill{{padding:8px 20px;border-radius:24px;font-size:18px;font-weight:700;
               background:{verdict_bg};color:{verdict_col};border:2px solid {verdict_col}}}
.risk-badge{{background:{risk_color};color:#fff;padding:2px 8px;border-radius:6px;
             font-size:11px;font-weight:700;letter-spacing:.5px}}
.section{{background:#fff;border-radius:12px;padding:20px 24px;
          box-shadow:0 1px 3px rgba(0,0,0,.1);margin-bottom:20px}}
.rationale{{background:#f0f9ff;border-left:4px solid #0ea5e9;padding:12px 16px;
            border-radius:0 8px 8px 0;color:#0c4a6e;font-size:13px;line-height:1.7}}
/* Pipeline */
.pipeline{{display:flex;flex-direction:column;gap:8px}}
.stage{{border-radius:8px;padding:12px 16px;transition:box-shadow .15s}}
.stage:hover{{box-shadow:0 4px 12px rgba(0,0,0,.12)}}
.stage-header{{display:flex;align-items:center;gap:8px;cursor:pointer}}
.stage-icon{{font-size:18px;width:28px;text-align:center}}
.stage-name{{font-weight:600;font-size:13px;flex:1}}
.stage-score{{font-size:12px;color:#64748b;font-family:monospace}}
.verdict-tag{{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;
              text-transform:uppercase;letter-spacing:.5px}}
.stage-detail{{margin-top:10px;padding-top:10px;border-top:1px solid rgba(0,0,0,.06);
               display:none;font-size:12px}}
.stage-detail.open{{display:block}}
.kv{{display:grid;grid-template-columns:180px 1fr;gap:4px 12px;color:#475569}}
.kv span:first-child{{color:#94a3b8}}
/* Counterfactuals */
.cf-table{{width:100%;border-collapse:collapse}}
.cf-table th{{text-align:left;font-size:11px;color:#94a3b8;text-transform:uppercase;
              letter-spacing:.5px;padding:6px 8px;border-bottom:2px solid #e2e8f0}}
.cf-table td{{padding:8px;border-bottom:1px solid #f1f5f9;font-size:12px;vertical-align:top}}
.cf-table tr:last-child td{{border-bottom:none}}
.sev-HIGH{{color:#ef4444;font-weight:700}}
.sev-MEDIUM{{color:#f59e0b;font-weight:700}}
.sev-LOW{{color:#22c55e;font-weight:700}}
/* JSON block */
details summary{{cursor:pointer;font-size:12px;color:#6366f1;user-select:none;padding:4px 0}}
pre{{background:#1e293b;color:#e2e8f0;padding:16px;border-radius:8px;
     font-size:11px;overflow-x:auto;line-height:1.6;margin-top:8px}}
/* Primary cause highlight */
.primary-cause{{outline:2px solid #f97316;outline-offset:2px}}
/* Footer */
.footer{{text-align:center;color:#94a3b8;font-size:11px;margin-top:32px;padding-top:16px;
         border-top:1px solid #e2e8f0}}
@media print{{
  body{{background:#fff}}
  .section,.header{{box-shadow:none;border:1px solid #e2e8f0}}
  details[open] summary::after{{content:""}}
}}
</style>
</head>
<body>
<div class="page">

<!-- Header -->
<div class="header">
  <div>
    <h1>Shadow Warden — XAI Decision Report</h1>
    <div class="header-meta">
      <div><b>Request ID</b>&nbsp;&nbsp;{_h(chain.request_id)}</div>
      <div><b>Tenant</b>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{_h(chain.tenant_id)}</div>
      <div><b>Timestamp</b>&nbsp;&nbsp;{_h(ts_fmt)}</div>
      {"<div><b>Pipeline</b>&nbsp;&nbsp;&nbsp;" + _h(f"{chain.processing_ms:.1f}ms") + "</div>" if chain.processing_ms else ""}
    </div>
  </div>
  <div style="text-align:right">
    <div class="verdict-pill">{_h(chain.final_verdict)}</div>
    <div style="margin-top:8px">
      <span class="risk-badge">{_h(chain.risk_level)} RISK</span>
    </div>
    <div style="margin-top:8px;font-size:12px;color:#94a3b8">
      Primary cause: <b>{_h(chain.primary_cause_name)}</b>
    </div>
  </div>
</div>

<!-- Rationale -->
<div class="section">
  <h2>Decision Rationale</h2>
  <div class="rationale">{_h(chain.rationale)}</div>
</div>

<!-- Pipeline -->
<div class="section">
  <h2>Pipeline Analysis</h2>
  <div class="pipeline">
    {nodes_html}
  </div>
</div>

<!-- Counterfactuals -->
{"" if not chain.counterfactuals else f'''<div class="section">
  <h2>Remediation — What Would Need to Change</h2>
  {cf_html}
</div>'''}

<!-- Raw chain JSON -->
<div class="section">
  <details>
    <summary>Raw Causal Chain JSON</summary>
    <pre>{chain_json}</pre>
  </details>
</div>

<div class="footer">
  Shadow Warden AI · XAI Report · Generated {datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S")} UTC
</div>
</div>
<script>
document.querySelectorAll('.stage-header').forEach(h=>{{
  h.addEventListener('click',()=>{{
    const d=h.closest('.stage').querySelector('.stage-detail');
    if(d) d.classList.toggle('open');
  }});
}});
</script>
</body>
</html>"""
    return page.encode("utf-8")


def _h(s: object) -> str:
    return _html.escape(str(s))


def _render_nodes(chain: CausalChain) -> str:
    parts: list[str] = []
    for node in chain.nodes:
        css   = _VERDICT_CSS.get(node.verdict, _VERDICT_CSS["SKIP"])
        v_col = {"BLOCK": "#ef4444", "FLAG": "#f59e0b", "PASS": "#22c55e", "SKIP": "#94a3b8"}
        tag_bg   = v_col.get(node.verdict, "#94a3b8")
        primary  = "primary-cause" if node.stage_id == chain.primary_cause else ""
        detail_html = _render_node_detail(node)
        parts.append(
            f'<div class="stage {primary}" style="{css}">'
            f'  <div class="stage-header">'
            f'    <span class="stage-icon">{_h(node.icon)}</span>'
            f'    <span class="stage-name">{_h(node.stage_name)}</span>'
            f'    <span class="stage-score">{_h(node.score_label)}</span>'
            f'    <span class="verdict-tag" style="background:{tag_bg};color:#fff">'
            f'      {_h(node.verdict)}'
            f'    </span>'
            f'  </div>'
            f'  {detail_html}'
            f'</div>'
        )
    return "\n".join(parts)


def _render_node_detail(node) -> str:
    if not node.detail:
        return ""
    rows = []
    for k, v in node.detail.items():
        if v is None:
            continue
        display = json.dumps(v) if isinstance(v, (list, dict)) else str(v)
        rows.append(
            f'<span>{_h(k)}</span>'
            f'<span style="font-family:monospace">{_h(display)}</span>'
        )
    if not rows:
        return ""
    return (
        '<div class="stage-detail">'
        '<div class="kv">'
        + "".join(rows)
        + "</div></div>"
    )


def _render_counterfactuals(chain: CausalChain) -> str:
    rows = "".join(
        f'<tr>'
        f'<td><span class="sev-{_h(c.severity)}">{_h(c.severity)}</span></td>'
        f'<td>{_h(STAGE_META_HTML.get(c.stage_id, c.stage_id))}</td>'
        f'<td>{_h(c.explanation)}</td>'
        f'</tr>'
        for c in chain.counterfactuals
    )
    return (
        '<table class="cf-table">'
        '<thead><tr><th>Severity</th><th>Stage</th><th>Recommended Action</th></tr></thead>'
        f'<tbody>{rows}</tbody>'
        '</table>'
    )


STAGE_META_HTML = {
    "topology":       "Topological Gatekeeper",
    "obfuscation":    "Obfuscation Decoder",
    "secrets":        "Secret Redactor",
    "semantic_rules": "Semantic Rule Engine",
    "brain":          "HyperbolicBrain (ML)",
    "causal":         "Causal Arbiter",
    "phish":          "PhishGuard",
    "ers":            "ERS + Shadow Ban",
    "decision":       "Final Decision",
}


# ── PDF renderer (reportlab optional) ────────────────────────────────────────

def render_pdf(chain: CausalChain) -> tuple[bytes, str]:
    """
    Render *chain* as PDF if reportlab is available.

    Returns:
        (content_bytes, content_type)
        content_type is "application/pdf" or "text/html; charset=utf-8" fallback.
    """
    try:
        return _render_pdf_reportlab(chain), "application/pdf"
    except ImportError:
        return render_html(chain), "text/html; charset=utf-8"


def _render_pdf_reportlab(chain: CausalChain) -> bytes:
    """Generate PDF using reportlab (raises ImportError if not installed)."""
    from io import BytesIO

    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buf    = BytesIO()
    doc    = SimpleDocTemplate(buf, pagesize=A4,
                               leftMargin=20*mm, rightMargin=20*mm,
                               topMargin=20*mm, bottomMargin=20*mm)
    styles = getSampleStyleSheet()
    story  = []

    # Title
    story.append(Paragraph(
        f"<b>Shadow Warden — XAI Decision Report</b>",
        styles["Title"],
    ))
    story.append(Spacer(1, 4*mm))

    # Meta table
    ts_fmt = chain.timestamp[:19].replace("T", " ") + " UTC" if chain.timestamp else "—"
    meta = [
        ["Request ID", chain.request_id],
        ["Tenant",     chain.tenant_id],
        ["Timestamp",  ts_fmt],
        ["Verdict",    chain.final_verdict],
        ["Risk Level", chain.risk_level],
        ["Primary Cause", chain.primary_cause_name],
        ["Processing", f"{chain.processing_ms:.1f}ms" if chain.processing_ms else "—"],
    ]
    meta_tbl = Table(meta, colWidths=[50*mm, 120*mm])
    meta_tbl.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#64748b")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID",      (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING",   (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 6*mm))

    # Rationale
    story.append(Paragraph("<b>Decision Rationale</b>", styles["Heading2"]))
    story.append(Paragraph(chain.rationale, styles["Normal"]))
    story.append(Spacer(1, 6*mm))

    # Pipeline table
    story.append(Paragraph("<b>Pipeline Analysis</b>", styles["Heading2"]))
    pipe_data = [["Stage", "Verdict", "Score", "Detail"]]
    _VERDICT_PDF_COLOR = {
        "BLOCK": colors.HexColor("#fecaca"),
        "FLAG":  colors.HexColor("#fef3c7"),
        "PASS":  colors.HexColor("#dcfce7"),
        "SKIP":  colors.HexColor("#f1f5f9"),
    }
    row_colors = [colors.HexColor("#1e293b")]   # header row color
    for node in chain.nodes:
        detail_str = ", ".join(
            f"{k}: {v}"
            for k, v in node.detail.items()
            if v is not None
        )[:80]
        pipe_data.append([node.stage_name, node.verdict, node.score_label, detail_str])
        row_colors.append(_VERDICT_PDF_COLOR.get(node.verdict, colors.white))

    pipe_tbl = Table(pipe_data, colWidths=[55*mm, 22*mm, 28*mm, None])
    pipe_tbl.setStyle(TableStyle([
        ("FONTNAME",   (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",   (0, 0), (-1, -1), 8),
        ("TEXTCOLOR",  (0, 0), (-1, 0),  colors.white),
        ("BACKGROUND", (0, 0), (-1, 0),  colors.HexColor("#1e293b")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [row_colors[i] for i in range(1, len(row_colors))]),
        ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("PADDING",    (0, 0), (-1, -1), 4),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ]))
    story.append(pipe_tbl)
    story.append(Spacer(1, 6*mm))

    # Counterfactuals
    if chain.counterfactuals:
        story.append(Paragraph("<b>Remediation Recommendations</b>", styles["Heading2"]))
        cf_data = [["Severity", "Stage", "Recommended Action"]]
        for c in chain.counterfactuals:
            cf_data.append([c.severity, STAGE_META_HTML.get(c.stage_id, c.stage_id), c.explanation])
        cf_tbl = Table(cf_data, colWidths=[22*mm, 45*mm, None])
        cf_tbl.setStyle(TableStyle([
            ("FONTNAME",   (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE",   (0, 0), (-1, -1), 8),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("PADDING",    (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(cf_tbl)

    # Footer
    story.append(Spacer(1, 8*mm))
    story.append(Paragraph(
        f"<font size='7' color='#94a3b8'>Generated by Shadow Warden AI · "
        f"{datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S')} UTC</font>",
        styles["Normal"],
    ))

    doc.build(story)
    return buf.getvalue()
