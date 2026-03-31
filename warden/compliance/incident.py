"""
warden/compliance/incident.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Incident Post-Mortem report generator.

Produces a structured report for any blocked agent session or ERS shadow-ban
entity.  Includes timeline, threat pattern analysis, attestation status, and
recommended remediation actions.

Report can be returned as JSON (always) or as styled HTML (browser → Print → PDF).
"""
from __future__ import annotations

from datetime import UTC, datetime

_RECOMMENDATIONS: dict[str, str] = {
    "RAPID_BLOCK":           "Review origin IP/tenant for automated scanning tools. Consider adding to blocklist via POST /threats/block.",
    "PRIVILEGE_ESCALATION":  "Audit agent manifest — ensure capabilities are scoped to minimum necessary tools. Revoke session if not yet done.",
    "EVASION_ATTEMPT":       "The agent retried a previously blocked tool. Indicates intentional evasion. Escalate to security team.",
    "EXFIL_CHAIN":           "Data read followed by network write. Review what data was accessed and whether it left the system.",
    "ROGUE_AGENT":           "Full kill-chain detected (read + write + destructive). Treat as confirmed compromise. Revoke all sessions for this tenant.",
    "TOOL_VELOCITY":         "Unusually high tool call rate. May indicate DoS or automated mass-exfiltration. Check rate limits.",
    "sandbox_violation":     "Tool call denied by capability manifest. Review agent manifest and reject manifest-override attempts.",
    "shadow_ban":            "Entity ERS score exceeded critical threshold. Shadow-ban is active — entity receives fake responses. Monitor for continued attempts.",
}


class IncidentReporter:
    """
    Generate a post-mortem incident report for a session or shadow-banned entity.

    Usage::

        reporter = IncidentReporter(agent_monitor=_agent_monitor)
        report = reporter.generate(session_id="sess-abc123")
        html   = reporter.to_html(report)
    """

    def __init__(self, agent_monitor=None) -> None:
        self._monitor = agent_monitor  # warden.agent_monitor.AgentMonitor | None

    def generate(
        self,
        session_id: str | None = None,
        entity_key: str | None = None,
    ) -> dict:
        """
        Build the incident report dict.

        At least one of *session_id* or *entity_key* must be supplied.
        """
        now = datetime.now(UTC).isoformat()

        report: dict = {
            "report_type":    "INCIDENT_POST_MORTEM",
            "schema_version": "1.0",
            "generated_at":   now,
            "session_id":     session_id,
            "entity_key":     entity_key,
            "summary":        {},
            "timeline":       [],
            "threats_detected":      [],
            "attestation":           {},
            "ers_profile":           {},
            "recommended_actions":   [],
            "error":                 "",
        }

        # ── Session data ───────────────────────────────────────────────────────
        if session_id and self._monitor is not None:
            sess = self._monitor.get_session(session_id)
            if sess is None:
                report["error"] = f"Session {session_id!r} not found in AgentMonitor store."
            else:
                threats = sess.get("threats_detected", [])
                events  = sess.get("events", [])
                tool_events   = [e for e in events if e.get("event_type") == "tool"]
                blocked_tools = [e for e in tool_events if e.get("blocked")]

                report["summary"] = {
                    "session_id":          session_id,
                    "tenant_id":           sess.get("tenant_id", "unknown"),
                    "first_seen":          sess.get("first_seen", ""),
                    "last_seen":           sess.get("last_seen", ""),
                    "risk_score":          sess.get("risk_score", 0.0),
                    "request_count":       sess.get("request_count", 0),
                    "block_count":         sess.get("block_count", 0),
                    "tool_event_count":    len(tool_events),
                    "blocked_tool_count":  len(blocked_tools),
                    "patterns_detected":   [t["pattern"] for t in threats],
                    "highest_severity":    _highest_severity(threats),
                    "revoked":             sess.get("revoked", False),
                    "attestation_valid":   None,  # filled below
                }

                # Attestation
                attest = self._monitor.verify_attestation(session_id)
                report["attestation"] = attest
                report["summary"]["attestation_valid"] = attest.get("valid")

                # Timeline — tool events only (no content, just metadata)
                report["timeline"] = [
                    {
                        "ts":          e.get("ts", ""),
                        "event_type":  e.get("event_type", ""),
                        "tool_name":   e.get("tool_name", ""),
                        "direction":   e.get("direction", ""),
                        "blocked":     e.get("blocked", False),
                        "threat_kind": e.get("threat_kind"),
                    }
                    for e in sorted(events, key=lambda x: x.get("ts", ""))
                    if e.get("event_type") == "tool"
                ]

                report["threats_detected"] = threats

                # Recommended actions
                seen_patterns: set[str] = set()
                for t in threats:
                    p = t.get("pattern", "")
                    if p and p not in seen_patterns:
                        seen_patterns.add(p)
                        if p in _RECOMMENDATIONS:
                            report["recommended_actions"].append({
                                "trigger": p,
                                "action":  _RECOMMENDATIONS[p],
                            })
                if not attest.get("valid") and attest.get("error") != "session_not_found":
                    report["recommended_actions"].append({
                        "trigger": "attestation_mismatch",
                        "action":  "Session history may have been tampered. Preserve the session record and escalate to security team immediately.",
                    })
                if sess.get("revoked"):
                    report["recommended_actions"].append({
                        "trigger": "session_revoked",
                        "action":  f"Session already revoked at {sess.get('revoked_at','unknown')}. Verify downstream systems are not still accepting requests from this agent.",
                    })

        # ── ERS profile ────────────────────────────────────────────────────────
        if entity_key:
            try:
                from warden import entity_risk as _ers  # noqa: PLC0415
                ers_result = _ers.score(entity_key)
                report["ers_profile"] = {
                    "entity_key":   entity_key,
                    "score":        ers_result.score,
                    "level":        ers_result.level,
                    "shadow_ban":   ers_result.shadow_ban,
                    "total_1h":     ers_result.total_1h,
                    "counts":       ers_result.counts,
                    "window_secs":  _ers.WINDOW_SECS,
                }
                if ers_result.shadow_ban:
                    report["recommended_actions"].append({
                        "trigger": "shadow_ban",
                        "action":  _RECOMMENDATIONS["shadow_ban"],
                    })
            except Exception as exc:
                report["ers_profile"] = {"error": str(exc)}

        return report

    # ── HTML renderer ─────────────────────────────────────────────────────────

    def to_html(self, report: dict) -> str:
        def _esc(s: str) -> str:
            return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        summary   = report.get("summary", {})
        threats   = report.get("threats_detected", [])
        timeline  = report.get("timeline", [])
        attest    = report.get("attestation", {})
        ers       = report.get("ers_profile", {})
        recs      = report.get("recommended_actions", [])
        gen_at    = report.get("generated_at", "")[:19].replace("T", " ")
        sid       = report.get("session_id", "N/A")
        ek        = report.get("entity_key", "N/A")
        err       = report.get("error", "")

        sev = summary.get("highest_severity", "")
        sev_color = {"HIGH": "#c62828", "MEDIUM": "#e65100"}.get(sev, "#2e7d32")

        threat_rows = "".join(
            f"<tr><td>{_esc(t.get('pattern',''))}</td>"
            f"<td style='color:{({'HIGH':'#c62828','MEDIUM':'#e65100'}.get(t.get('severity',''),''))}'>"
            f"{_esc(t.get('severity',''))}</td>"
            f"<td>{_esc(t.get('detail',''))}</td>"
            f"<td>{_esc(t.get('detected_at',''))[:19]}</td></tr>"
            for t in threats
        )

        timeline_rows = "".join(
            f"<tr><td>{_esc(e.get('ts',''))[:19]}</td>"
            f"<td>{_esc(e.get('tool_name',''))}</td>"
            f"<td>{_esc(e.get('direction',''))}</td>"
            f"<td style='color:{'#c62828' if e.get('blocked') else '#2e7d32'}'>"
            f"{'BLOCKED' if e.get('blocked') else 'allowed'}</td>"
            f"<td>{_esc(e.get('threat_kind','') or '')}</td></tr>"
            for e in timeline
        )

        rec_items = "".join(
            f"<li><strong>{_esc(r.get('trigger',''))}:</strong> {_esc(r.get('action',''))}</li>"
            for r in recs
        )

        attest_color = "#2e7d32" if attest.get("valid") else "#c62828"
        attest_label = "VALID" if attest.get("valid") else ("NOT VERIFIED" if attest else "N/A")

        ers_html = ""
        if ers and not ers.get("error"):
            level_color = {"low": "#2e7d32", "medium": "#e65100", "high": "#c62828", "critical": "#7b1fa2"}.get(ers.get("level", ""), "#333")
            ers_html = f"""
            <h2>Entity Risk Score</h2>
            <table>
              <tr><td class='lbl'>Entity Key</td><td>{_esc(str(ers.get('entity_key',''))[:16])}</td></tr>
              <tr><td class='lbl'>Score</td><td><strong>{ers.get('score',0):.3f}</strong></td></tr>
              <tr><td class='lbl'>Level</td><td style='color:{level_color};font-weight:700'>{_esc(str(ers.get('level',''))).upper()}</td></tr>
              <tr><td class='lbl'>Shadow Ban Active</td><td>{'YES' if ers.get('shadow_ban') else 'No'}</td></tr>
              <tr><td class='lbl'>Requests (1h window)</td><td>{ers.get('total_1h',0)}</td></tr>
              <tr><td class='lbl'>Event Counts</td><td>{_esc(json_inline(ers.get('counts',{})))}</td></tr>
            </table>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Incident Report — {_esc(sid)}</title>
<style>
  body{{font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#222;margin:0;padding:0}}
  .header{{background:#c62828;color:#fff;padding:24px 36px}}
  .header h1{{margin:0 0 4px;font-size:20px}}
  .header p{{margin:0;font-size:12px;opacity:.9}}
  .body{{padding:28px 36px}}
  h2{{color:#1a1a2e;border-bottom:2px solid #1a1a2e;padding-bottom:4px;margin-top:28px}}
  .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:20px}}
  .stat{{border:1px solid #ddd;border-radius:6px;padding:12px;text-align:center;background:#fafafa}}
  .stat .n{{font-size:22px;font-weight:700;color:#1a1a2e}}
  .stat .l{{font-size:11px;color:#666;margin-top:3px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:12px}}
  th{{background:#1a1a2e;color:#fff;padding:6px 8px;text-align:left;font-size:12px}}
  td{{padding:5px 8px;border:1px solid #ddd;vertical-align:top}}
  td.lbl{{width:200px;font-weight:600;background:#f5f5f5}}
  .attest{{display:inline-block;padding:3px 12px;border-radius:4px;font-weight:700;
           color:#fff;background:{attest_color};margin-left:8px;font-size:12px}}
  .sev{{display:inline-block;padding:3px 12px;border-radius:4px;font-weight:700;
        color:#fff;background:{sev_color}}}
  ul.recs{{line-height:2}}
  .err{{background:#fff3e0;border:1px solid #ffb300;padding:10px;border-radius:4px;color:#e65100}}
  .footer{{font-size:10px;color:#999;border-top:1px solid #eee;padding:12px 36px;margin-top:20px}}
  @media print{{.header{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}}}
</style>
</head>
<body>
<div class="header">
  <h1>Incident Post-Mortem Report</h1>
  <p>Session: {_esc(sid)} &nbsp;|&nbsp; Entity: {_esc(str(ek)[:16])} &nbsp;|&nbsp; Generated: {_esc(gen_at)} UTC</p>
</div>
<div class="body">
{'<div class="err">' + _esc(err) + '</div>' if err else ''}

  <h2>Summary
    {'<span class="sev">' + _esc(sev) + '</span>' if sev else ''}
    <span class="attest">{attest_label}</span>
  </h2>
  <div class="stats">
    <div class="stat"><div class="n">{summary.get('request_count',0)}</div><div class="l">Requests</div></div>
    <div class="stat"><div class="n">{summary.get('block_count',0)}</div><div class="l">Blocks</div></div>
    <div class="stat"><div class="n">{summary.get('tool_event_count',0)}</div><div class="l">Tool Events</div></div>
    <div class="stat"><div class="n">{summary.get('blocked_tool_count',0)}</div><div class="l">Blocked Tool Calls</div></div>
  </div>
  <table>
    <tr><td class='lbl'>Tenant</td><td>{_esc(str(summary.get('tenant_id','')))}</td></tr>
    <tr><td class='lbl'>First Seen</td><td>{_esc(str(summary.get('first_seen',''))[:19])}</td></tr>
    <tr><td class='lbl'>Last Seen</td><td>{_esc(str(summary.get('last_seen',''))[:19])}</td></tr>
    <tr><td class='lbl'>Risk Score</td><td><strong>{summary.get('risk_score',0):.4f}</strong></td></tr>
    <tr><td class='lbl'>Session Revoked</td><td>{'YES' if summary.get('revoked') else 'No'}</td></tr>
    <tr><td class='lbl'>Attestation Chain</td><td style='color:{attest_color};font-weight:700'>{attest_label}
      {'— stored: ' + _esc(str(attest.get('stored_token',''))[:16]) if attest else ''}</td></tr>
  </table>

  {ers_html}

  <h2>Threats Detected ({len(threats)})</h2>
  {'<table><tr><th>Pattern</th><th>Severity</th><th>Detail</th><th>Detected At</th></tr>' + threat_rows + '</table>' if threats else '<p style="color:#666">No threat patterns detected.</p>'}

  <h2>Tool Call Timeline ({len(timeline)} events)</h2>
  {'<table><tr><th>Time</th><th>Tool</th><th>Direction</th><th>Decision</th><th>Threat Kind</th></tr>' + timeline_rows + '</table>' if timeline else '<p style="color:#666">No tool events recorded.</p>'}

  <h2>Recommended Actions ({len(recs)})</h2>
  {'<ul class="recs">' + rec_items + '</ul>' if recs else '<p style="color:#2e7d32">No immediate actions required.</p>'}

</div>
<div class="footer">
  Generated by Shadow Warden AI Compliance Module v2.3 &nbsp;|&nbsp;
  Session ID: {_esc(sid)} &nbsp;|&nbsp;
  This report contains metadata only — no prompt or response content.
</div>
</body>
</html>"""


def json_inline(obj: object) -> str:
    import json  # noqa: PLC0415
    return json.dumps(obj, separators=(", ", ": "))


def _highest_severity(threats: list[dict]) -> str:
    for sev in ("HIGH", "MEDIUM"):
        if any(t.get("severity") == sev for t in threats):
            return sev
    return ""
