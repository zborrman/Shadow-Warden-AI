"""
warden/compliance/art30.py
━━━━━━━━━━━━━━━━━━━━━━━━━
GDPR Article 30 — Record of Processing Activities (RoPA) generator.

Compiles a complete Art. 30 record from real traffic data logged by
warden/analytics/logger.py.  The record is backed by actual metrics
(request counts, entity types, flag distribution, retention settings)
so the DPO is filing evidence-based documentation, not guesswork.

Environment variables (controller identity — set in .env or Docker secrets)
─────────────────────────────────────────────────────────────────────────────
  CONTROLLER_NAME        Legal name of the data controller
  CONTROLLER_ADDRESS     Registered address
  CONTROLLER_EMAIL       General contact e-mail
  DPO_NAME               Data Protection Officer name (if appointed)
  DPO_EMAIL              DPO contact e-mail
  THIRD_COUNTRY_TRANSFER "true" if data is transferred outside EU/EEA
  THIRD_COUNTRY_NAME     Target country name (e.g. "United States")
  THIRD_COUNTRY_SAFEGUARD Safeguard in place (e.g. "Standard Contractual Clauses")
"""
from __future__ import annotations

import os
from collections import Counter
from datetime import UTC, datetime, timedelta

# ── Controller identity (from env — never hardcoded) ─────────────────────────

def _ctrl(key: str, fallback: str = "") -> str:
    return os.getenv(key, fallback)


# ── Security measures actually implemented by Warden ─────────────────────────

_SECURITY_MEASURES = [
    "SHA-256[:16] pseudonymisation of all entity identifiers (tenant_id + IP) — no raw PII stored",
    "TLS 1.2+ encryption in transit (nginx proxy layer)",
    "Zero content-logging policy: prompt/response content is NEVER written to any log or database",
    "Cryptographic hash-chain audit trail (SQLite WAL mode, tamper-evident via SHA-256 chaining)",
    "Atomic log writes using tempfile + os.replace() to prevent corruption",
    "Per-tenant rate limiting (configurable, default 60 req/min)",
    "Sliding-window Entity Risk Scoring: behavioural threat scoring without storing personal data",
    "Shadow-ban covert neutralisation: confirmed attackers receive fake responses without content processing",
    "Zero-Trust Agent Sandbox: capability manifests with default-deny for agentic tool calls",
    "Session kill-switch: instant revocation of compromised agent sessions",
    "Automated corpus evolution with poisoning protection (growth cap, vetting, dedup)",
    "GDPR erasure endpoint: POST /gdpr/purge removes all log entries for a request_id",
    "Data minimisation: only metadata (length, flags, timing) logged — not content",
]


# ── Main generator ────────────────────────────────────────────────────────────

class Art30Generator:
    """
    Generate a GDPR Article 30 Record of Processing Activities.

    Usage::

        gen = Art30Generator()
        record = gen.generate(days=30)   # JSON-serialisable dict
        html   = gen.to_html(record)     # styled HTML for DPO sign-off
    """

    def generate(self, days: float = 30) -> dict:
        """
        Build the Art. 30 record from live traffic data.

        *days* controls how far back logs are scanned for the traffic summary.
        The record structure itself covers the controller's processing operations
        regardless of the window size.
        """
        from warden.analytics.logger import (  # noqa: PLC0415
            LOG_RETENTION_DAYS,
            LOGS_PATH,
            load_entries,
        )

        now       = datetime.now(UTC)
        start_iso = (now - timedelta(days=days)).isoformat()
        end_iso   = now.isoformat()

        entries   = load_entries(days=days)
        total     = len(entries)
        blocked   = sum(1 for e in entries if not e.get("allowed", True))
        secrets   = sum(len(e.get("secrets_found", [])) for e in entries)
        masked    = sum(1 for e in entries if e.get("masked", False))

        flag_counts: Counter[str] = Counter()
        entity_type_counts: Counter[str] = Counter()
        for e in entries:
            for f in e.get("flags", []):
                flag_counts[f] += 1
            for et in e.get("entities_detected", []):
                entity_type_counts[et] += 1

        third_country = _ctrl("THIRD_COUNTRY_TRANSFER", "false").lower() == "true"

        record = {
            "record_type":    "GDPR_ART30_RECORD_OF_PROCESSING_ACTIVITIES",
            "schema_version": "1.0",
            "generated_at":   now.isoformat(),
            "report_period": {
                "start": start_iso,
                "end":   end_iso,
                "days":  days,
            },

            # ── Controller ────────────────────────────────────────────
            "controller": {
                "name":      _ctrl("CONTROLLER_NAME",    "Shadow Warden AI Operator"),
                "address":   _ctrl("CONTROLLER_ADDRESS", ""),
                "email":     _ctrl("CONTROLLER_EMAIL",   ""),
                "dpo_name":  _ctrl("DPO_NAME",  ""),
                "dpo_email": _ctrl("DPO_EMAIL", ""),
            },

            # ── Processing activities ──────────────────────────────────
            "processing_activities": [
                {
                    "id":      "PA-001",
                    "name":    "AI Request Security Filtering",
                    "purpose": (
                        "Detection and prevention of malicious AI prompt injections, "
                        "jailbreak attempts, sensitive data exfiltration, and obfuscated "
                        "attack payloads before they reach downstream AI models or APIs."
                    ),
                    "legal_basis": (
                        "Article 6(1)(f) GDPR — Legitimate interests of the controller "
                        "(protection of information systems and prevention of fraud)."
                    ),
                    "data_subjects":  "API consumers and end-users submitting AI inference requests",
                    "data_categories": [
                        "Pseudonymised entity key (SHA-256[:16] of tenant_id:IP — not reversible to PII)",
                        "Request metadata: payload length (bytes), token count estimate",
                        "Timing metadata: processing duration per pipeline stage (ms)",
                        "Risk classification: allowed/blocked, risk level (low/medium/high/block)",
                        "Flag types: category labels of detected threats (e.g. 'jailbreak', 'pii') — NOT content values",
                        "PII entity types detected (e.g. 'email', 'ssn') — NOT actual values",
                        "Session identifier (if provided by the API consumer)",
                    ],
                    "data_not_collected": (
                        "Prompt content, response content, personal data values, raw IP addresses, "
                        "usernames, or any reversible identifier. Zero-content-logging by design."
                    ),
                    "recipients":         "None — all data is processed and stored within the system boundary",
                    "third_country_transfer": third_country,
                    "third_country_name":      _ctrl("THIRD_COUNTRY_NAME", "") if third_country else None,
                    "third_country_safeguard": _ctrl("THIRD_COUNTRY_SAFEGUARD", "") if third_country else None,
                    "retention_policy": {
                        "log_retention_days":     LOG_RETENTION_DAYS,
                        "session_ttl_seconds":    int(os.getenv("AGENT_SESSION_TTL", "1800")),
                        "ers_window_seconds":     int(os.getenv("ERS_WINDOW_SECS", "3600")),
                        "audit_db_path":          os.getenv("AUDIT_DB_PATH", "/warden/data/audit.db"),
                        "erasure_endpoint":       "POST /gdpr/purge (request_id-level erasure)",
                    },
                    "automated_decision_making": {
                        "applies":  True,
                        "basis":    (
                            "Automated rule-based and ML scoring pipeline. "
                            "No solely-automated decisions with legal/significant effect on data subjects. "
                            "Human override available via POST /ers/reset (false-positive clearance)."
                        ),
                    },
                    "security_measures": _SECURITY_MEASURES,
                },
                {
                    "id":      "PA-002",
                    "name":    "Agentic Tool-Use Monitoring",
                    "purpose": (
                        "Detection of rogue or compromised AI agent behaviours "
                        "(privilege escalation, exfiltration chains, kill-chain sequences) "
                        "across multi-step tool-use sessions."
                    ),
                    "legal_basis": (
                        "Article 6(1)(f) GDPR — Legitimate interests "
                        "(prevention of automated system abuse)."
                    ),
                    "data_subjects":  "Operators deploying AI agents through the gateway",
                    "data_categories": [
                        "Session identifier (operator-supplied or generated)",
                        "Tool function names (not arguments or outputs)",
                        "Tool call direction (call/result) and blocked status",
                        "Session-level threat pattern labels",
                        "SHA-256 attestation token (cryptographic chain — no content)",
                    ],
                    "data_not_collected": "Tool arguments, tool results, prompt content",
                    "recipients":         "None",
                    "third_country_transfer": False,
                    "retention_policy": {
                        "session_ttl_seconds": int(os.getenv("AGENT_SESSION_TTL", "1800")),
                    },
                    "automated_decision_making": {
                        "applies":  True,
                        "basis":    (
                            "Pattern-based session analysis. "
                            "Kill-switch requires human administrator action (DELETE /api/agent/session/{id})."
                        ),
                    },
                    "security_measures": _SECURITY_MEASURES,
                },
            ],

            # ── Traffic summary (evidence from actual logs) ────────────
            "traffic_summary": {
                "period_days":           days,
                "total_requests":        total,
                "blocked_requests":      blocked,
                "allowed_requests":      total - blocked,
                "block_rate_pct":        round(blocked / total * 100, 2) if total else 0.0,
                "secrets_detected":      secrets,
                "pii_masked_requests":   masked,
                "top_threat_flags":      flag_counts.most_common(10),
                "pii_entity_types_seen": dict(entity_type_counts),
                "log_file":              str(LOGS_PATH),
            },
        }
        return record

    # ── HTML renderer ─────────────────────────────────────────────────────────

    def to_html(self, record: dict) -> str:
        ctrl   = record.get("controller", {})
        period = record.get("report_period", {})
        ts     = record.get("generated_at", "")[:10]
        stats  = record.get("traffic_summary", {})

        def _row(label: str, value: object) -> str:
            return f"<tr><td class='lbl'>{label}</td><td>{_esc(str(value))}</td></tr>"

        def _esc(s: str) -> str:
            return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        acts_html = ""
        for act in record.get("processing_activities", []):
            measures_li = "".join(
                f"<li>{_esc(m)}</li>" for m in act.get("security_measures", [])
            )
            cats_li = "".join(
                f"<li>{_esc(c)}</li>" for c in act.get("data_categories", [])
            )
            retention = act.get("retention_policy", {})
            adr = act.get("automated_decision_making", {})
            tc  = act.get("third_country_transfer", False)
            acts_html += f"""
            <div class="activity">
              <h3>{_esc(act.get('id',''))} — {_esc(act.get('name',''))}</h3>
              <table>
                {_row('Purpose', act.get('purpose',''))}
                {_row('Legal Basis', act.get('legal_basis',''))}
                {_row('Data Subjects', act.get('data_subjects',''))}
                {_row('Data NOT Collected', act.get('data_not_collected',''))}
                {_row('Recipients', act.get('recipients',''))}
                {_row('Third-Country Transfer', 'Yes — ' + act.get('third_country_name','') + ' (' + act.get('third_country_safeguard','') + ')' if tc else 'No')}
                {_row('Retention', '; '.join(f'{k}={v}' for k,v in retention.items()))}
                {_row('Automated Decisions', adr.get('basis',''))}
              </table>
              <p><strong>Data Categories</strong></p>
              <ul>{cats_li}</ul>
              <p><strong>Technical &amp; Organisational Measures</strong></p>
              <ul>{measures_li}</ul>
            </div>"""

        flags_rows = "".join(
            f"<tr><td>{_esc(f)}</td><td>{c}</td></tr>"
            for f, c in stats.get("top_threat_flags", [])
        )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>GDPR Art. 30 Record — {ts}</title>
<style>
  body{{font-family:Arial,Helvetica,sans-serif;font-size:13px;color:#222;margin:0;padding:0}}
  .header{{background:#1a1a2e;color:#fff;padding:24px 36px}}
  .header h1{{margin:0 0 4px;font-size:20px;letter-spacing:.5px}}
  .header p{{margin:0;font-size:12px;opacity:.8}}
  .body{{padding:28px 36px}}
  .badge{{display:inline-block;background:#e8f5e9;color:#2e7d32;border:1px solid #a5d6a7;
          border-radius:4px;padding:2px 10px;font-size:11px;font-weight:700;margin-bottom:16px}}
  h2{{color:#1a1a2e;border-bottom:2px solid #1a1a2e;padding-bottom:4px;margin-top:28px}}
  h3{{color:#333;margin-top:16px;margin-bottom:6px}}
  table{{width:100%;border-collapse:collapse;margin-bottom:12px}}
  td{{padding:5px 8px;border:1px solid #ddd;vertical-align:top}}
  td.lbl{{width:220px;font-weight:600;background:#f5f5f5;color:#444}}
  .activity{{border:1px solid #ccc;border-radius:6px;padding:16px 20px;margin-bottom:20px;background:#fafafa}}
  .stats{{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:20px}}
  .stat{{background:#1a1a2e;color:#fff;border-radius:6px;padding:14px;text-align:center}}
  .stat .n{{font-size:26px;font-weight:700;color:#64b5f6}}
  .stat .l{{font-size:11px;opacity:.8;margin-top:4px}}
  ul{{margin:4px 0 8px 0;padding-left:20px;line-height:1.7}}
  .footer{{font-size:10px;color:#999;border-top:1px solid #eee;padding:12px 36px;margin-top:20px}}
  @media print{{.header{{-webkit-print-color-adjust:exact;print-color-adjust:exact}}}}
</style>
</head>
<body>
<div class="header">
  <h1>GDPR Article 30 — Record of Processing Activities</h1>
  <p>Controller: {_esc(ctrl.get('name',''))} &nbsp;|&nbsp;
     Generated: {_esc(ts)} &nbsp;|&nbsp;
     Period: {_esc(period.get('start','')[:10])} → {_esc(period.get('end','')[:10])}</p>
</div>
<div class="body">
  <span class="badge">GDPR Art. 30(1) Compliant Record</span>

  <h2>Controller</h2>
  <table>
    {_row('Name', ctrl.get('name',''))}
    {_row('Address', ctrl.get('address','') or '(see configuration)')}
    {_row('Contact', ctrl.get('email','') or '(see configuration)')}
    {_row('DPO Name', ctrl.get('dpo_name','') or '(not appointed or see configuration)')}
    {_row('DPO Email', ctrl.get('dpo_email','') or '(not appointed or see configuration)')}
  </table>

  <h2>Traffic Evidence Summary (last {period.get('days',30):.0f} days)</h2>
  <div class="stats">
    <div class="stat"><div class="n">{stats.get('total_requests',0):,}</div><div class="l">Total Requests Processed</div></div>
    <div class="stat"><div class="n">{stats.get('blocked_requests',0):,}</div><div class="l">Threats Blocked</div></div>
    <div class="stat"><div class="n">{stats.get('block_rate_pct',0):.1f}%</div><div class="l">Block Rate</div></div>
    <div class="stat"><div class="n">{stats.get('secrets_detected',0):,}</div><div class="l">Secrets Detected</div></div>
    <div class="stat"><div class="n">{stats.get('pii_masked_requests',0):,}</div><div class="l">Requests PII-Masked</div></div>
    <div class="stat"><div class="n">{stats.get('allowed_requests',0):,}</div><div class="l">Clean Requests Passed</div></div>
  </div>
  {"<table><tr><th>Flag</th><th>Count</th></tr>" + flags_rows + "</table>" if flags_rows else ""}

  <h2>Processing Activities</h2>
  {acts_html}

</div>
<div class="footer">
  Generated by Shadow Warden AI Compliance Module v2.3 &nbsp;|&nbsp;
  This document constitutes the Article 30 record as required under GDPR for the controller named above. &nbsp;|&nbsp;
  File: {_esc(stats.get('log_file',''))}
</div>
</body>
</html>"""
