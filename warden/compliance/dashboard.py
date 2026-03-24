"""
warden/compliance/dashboard.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Compliance & Risk Mitigation Dashboard — ROI metrics.

Turns raw security telemetry into business-value numbers a CISO can
present to the board or include in a SOC 2 management assertion.

ROI model
─────────
  Shadow Ban savings:
    Each shadow-banned request that never reaches the downstream LLM saves
    the full inference cost.  Default assumption: avg 500 tokens input,
    $0.15/1M tokens (GPT-4o-mini tier) → ~$0.000075/request.
    Configure via COMPLIANCE_LLM_COST_PER_TOKEN_USD.

  Breach cost avoided:
    Each HIGH/BLOCK decision averted a potential data-exfiltration event.
    Industry median breach cost: $4.45M (IBM 2023), divided by estimated
    annual incidents to get a per-event avoided cost.
    Configure via COMPLIANCE_BREACH_COST_USD and COMPLIANCE_BREACH_INCIDENTS_PER_YEAR.

  Secret redaction savings:
    Each PII/secret redaction prevented a potential credential-exposure event.
    Conservative estimate: $50k per credential exposure (account takeover chain).
    Configure via COMPLIANCE_CREDENTIAL_EXPOSURE_COST_USD.

All defaults are conservative and clearly documented; operators should
override them with their own actuarial figures via environment variables.
"""
from __future__ import annotations

import os
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path


# ── ROI model constants ───────────────────────────────────────────────────────

_LLM_COST_PER_TOKEN = float(os.getenv(
    "COMPLIANCE_LLM_COST_PER_TOKEN_USD", str(0.15 / 1_000_000)
))
_AVG_SHADOW_BAN_TOKENS = int(os.getenv("COMPLIANCE_AVG_SHADOW_BAN_TOKENS", "500"))

_BREACH_COST_USD = float(os.getenv("COMPLIANCE_BREACH_COST_USD", "4_450_000"))
_BREACH_PER_YEAR = float(os.getenv("COMPLIANCE_BREACH_INCIDENTS_PER_YEAR", "2"))

_CREDENTIAL_EXPOSURE_USD = float(os.getenv(
    "COMPLIANCE_CREDENTIAL_EXPOSURE_COST_USD", "50_000"
))


class ComplianceDashboard:
    """
    Compute compliance ROI metrics from live telemetry.

    Usage::

        dash = ComplianceDashboard(agent_monitor=_agent_monitor)
        metrics = dash.get_metrics(days=30)
    """

    def __init__(self, agent_monitor=None) -> None:
        self._monitor = agent_monitor  # warden.agent_monitor.AgentMonitor | None

    def get_metrics(self, days: float = 30) -> dict:
        from warden.analytics.logger import load_entries  # noqa: PLC0415

        now     = datetime.now(UTC)
        entries = load_entries(days=days)
        total   = len(entries)
        blocked = sum(1 for e in entries if not e.get("allowed", True))

        flag_counts: Counter[str] = Counter()
        secret_counts: Counter[str] = Counter()
        total_attack_cost = 0.0
        total_tokens      = 0

        for e in entries:
            for f in e.get("flags", []):
                flag_counts[f] += 1
            for s in e.get("secrets_found", []):
                secret_counts[s] += 1
            total_attack_cost += e.get("attack_cost_usd", 0.0)
            total_tokens      += e.get("payload_tokens", 0)

        # ── Shadow ban metrics ────────────────────────────────────────────────
        # We infer shadow-ban events from ERS critical-level entities in logs.
        # Approximation: requests flagged as shadow-banned are those that would
        # have been blocked but were instead served fake responses.
        # We use the "ers_shadow_ban" flag if present, else fall back to 0.
        shadow_ban_count = sum(1 for e in entries if "shadow_ban" in e.get("flags", []))
        shadow_ban_tokens_saved = shadow_ban_count * _AVG_SHADOW_BAN_TOKENS
        shadow_ban_cost_saved   = shadow_ban_tokens_saved * _LLM_COST_PER_TOKEN

        # ── Breach cost avoided ───────────────────────────────────────────────
        # One HIGH/BLOCK = one averted incident.
        # Annualised: (blocked / days * 365) events per year avoided.
        high_blocks     = sum(1 for e in entries if e.get("risk_level") in ("high", "block"))
        breach_per_event = _BREACH_COST_USD / max(_BREACH_PER_YEAR * 365, 1)
        breach_avoided  = round(high_blocks * breach_per_event, 2)

        # ── Secret / credential protection ───────────────────────────────────
        secrets_total   = sum(1 for e in entries for _ in e.get("secrets_found", []))
        credential_cost = round(secrets_total * _CREDENTIAL_EXPOSURE_USD, 2)

        # ── Evolution engine ──────────────────────────────────────────────────
        rules_count = 0
        rules_path  = Path(os.getenv("DYNAMIC_RULES_PATH", "/warden/data/dynamic_rules.json"))
        if rules_path.exists():
            try:
                import json  # noqa: PLC0415
                data = json.loads(rules_path.read_text())
                rules_count = len([r for r in data.get("rules", []) if r.get("status") == "active"])
            except Exception:
                pass

        # ── Agent security ────────────────────────────────────────────────────
        sessions_monitored = 0
        sessions_revoked   = 0
        rogue_agents       = 0
        if self._monitor is not None:
            try:
                sessions = self._monitor.list_sessions(limit=9999)
                sessions_monitored = len(sessions)
                sessions_revoked   = sum(1 for s in sessions if s.get("revoked"))
                rogue_agents = sum(
                    1 for s in sessions
                    if any(t.get("pattern") == "ROGUE_AGENT" for t in s.get("threats_detected", []))
                )
            except Exception:
                pass

        total_roi = round(shadow_ban_cost_saved + breach_avoided + credential_cost, 2)

        return {
            "generated_at":  now.isoformat(),
            "period_days":   days,
            "assumptions": {
                "llm_cost_per_token_usd":         _LLM_COST_PER_TOKEN,
                "avg_shadow_ban_tokens":           _AVG_SHADOW_BAN_TOKENS,
                "breach_cost_usd":                 _BREACH_COST_USD,
                "breach_incidents_per_year":       _BREACH_PER_YEAR,
                "credential_exposure_cost_usd":    _CREDENTIAL_EXPOSURE_USD,
                "note": "Override via COMPLIANCE_* environment variables with your organisation's figures.",
            },
            "traffic": {
                "total_requests":       total,
                "blocked_requests":     blocked,
                "block_rate_pct":       round(blocked / total * 100, 2) if total else 0.0,
                "total_payload_tokens": total_tokens,
                "attacker_cost_usd":    round(total_attack_cost, 6),
                "top_threat_flags":     dict(flag_counts.most_common(10)),
            },
            "shadow_ban": {
                "requests_deflected":      shadow_ban_count,
                "tokens_not_processed":    shadow_ban_tokens_saved,
                "compute_cost_saved_usd":  round(shadow_ban_cost_saved, 6),
                "explanation": (
                    "Shadow-banned entities received plausible fake responses. "
                    "The LLM backend was never called, saving full inference cost."
                ),
            },
            "threat_mitigation": {
                "high_block_events":             high_blocks,
                "estimated_breach_cost_avoided": breach_avoided,
                "secret_types_detected":         dict(secret_counts.most_common()),
                "secrets_redacted":              secrets_total,
                "explanation": (
                    f"Each HIGH/BLOCK event averted an estimated "
                    f"${breach_per_event:,.0f} in breach cost "
                    f"(IBM 2023 median ${_BREACH_COST_USD:,.0f} / "
                    f"{_BREACH_PER_YEAR} incidents/yr / 365 days)."
                ),
            },
            "secret_protection": {
                "total_secrets_redacted":            secrets_total,
                "estimated_credential_cost_avoided": credential_cost,
                "explanation": (
                    f"Each redacted credential averts an estimated "
                    f"${_CREDENTIAL_EXPOSURE_USD:,.0f} exposure cost."
                ),
            },
            "evolution_engine": {
                "active_evolved_rules": rules_count,
                "explanation": (
                    "Rules auto-generated by Claude Opus from blocked attack patterns. "
                    "Each rule extends coverage without engineering effort."
                ),
            },
            "agent_security": {
                "sessions_monitored":    sessions_monitored,
                "sessions_revoked":      sessions_revoked,
                "rogue_agents_detected": rogue_agents,
            },
            "roi_summary": {
                "shadow_ban_savings_usd":         round(shadow_ban_cost_saved, 2),
                "breach_cost_avoided_usd":        breach_avoided,
                "credential_exposure_avoided_usd": credential_cost,
                "total_estimated_roi_usd":        total_roi,
                "explanation": (
                    "Conservative estimate. Override COMPLIANCE_* env vars "
                    "with your organisation's actual LLM pricing and breach cost data."
                ),
            },
        }


def _highest_severity(threats: list[dict]) -> str:
    for sev in ("HIGH", "MEDIUM"):
        if any(t.get("severity") == sev for t in threats):
            return sev
    return ""
