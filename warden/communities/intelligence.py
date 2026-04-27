"""
warden/communities/intelligence.py
────────────────────────────────────
Community Intelligence Report — Risk scoring + Transfer analytics.

Aggregates data from:
  • behavioral.py   — anomaly history, event baselines
  • stix_audit.py   — transfer chain (ACCEPTED/REJECTED counts)
  • peering.py      — active peerins, policy breakdown
  • quota.py        — storage / bandwidth utilisation
  • charter.py      — governance compliance rate (% members accepted)

Output: CommunityIntelReport (JSON-serialisable) used by:
  • GET /community-intel/{community_id}          → JSON
  • GET /community-intel/{community_id}/pdf      → HTML or PDF
  • analytics/pages/4_Community.py              → Streamlit dashboard
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

log = logging.getLogger("warden.communities.intelligence")

_SEP_DB_PATH      = os.getenv("SEP_DB_PATH", "/tmp/warden_sep.db")
_REGISTRY_DB_PATH = os.getenv("COMMUNITY_REGISTRY_PATH", "/tmp/warden_community_registry.db")
_BEHAVIORAL_DB    = os.getenv("BEHAVIORAL_DB_PATH", "/tmp/warden_behavioral.db")


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class TransferStats:
    total: int = 0
    accepted: int = 0
    rejected: int = 0
    by_data_class: dict[str, int] = field(default_factory=dict)
    top_target_communities: list[dict] = field(default_factory=list)


@dataclass
class PeeringStats:
    total: int = 0
    active: int = 0
    revoked: int = 0
    by_policy: dict[str, int] = field(default_factory=dict)


@dataclass
class GovernanceStats:
    charter_active: bool = False
    charter_version: int = 0
    acceptance_rate: float = 0.0
    pending_acceptances: int = 0


@dataclass
class RiskScore:
    overall: float = 0.0            # 0.0 (safe) – 1.0 (critical)
    anomaly_score: float = 0.0
    transfer_rejection_rate: float = 0.0
    governance_gap: float = 0.0
    label: str = "SAFE"             # SAFE | LOW | MEDIUM | HIGH | CRITICAL


@dataclass
class CommunityIntelReport:
    community_id: str
    generated_at: str
    risk: RiskScore
    transfers: TransferStats
    peerings: PeeringStats
    governance: GovernanceStats
    recent_anomalies: list[dict] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "community_id":   self.community_id,
            "generated_at":   self.generated_at,
            "risk": {
                "overall":                  round(self.risk.overall, 3),
                "anomaly_score":            round(self.risk.anomaly_score, 3),
                "transfer_rejection_rate":  round(self.risk.transfer_rejection_rate, 3),
                "governance_gap":           round(self.risk.governance_gap, 3),
                "label":                    self.risk.label,
            },
            "transfers": {
                "total":                  self.transfers.total,
                "accepted":               self.transfers.accepted,
                "rejected":               self.transfers.rejected,
                "by_data_class":          self.transfers.by_data_class,
                "top_target_communities": self.transfers.top_target_communities,
            },
            "peerings": {
                "total":     self.peerings.total,
                "active":    self.peerings.active,
                "revoked":   self.peerings.revoked,
                "by_policy": self.peerings.by_policy,
            },
            "governance": {
                "charter_active":      self.governance.charter_active,
                "charter_version":     self.governance.charter_version,
                "acceptance_rate":     round(self.governance.acceptance_rate, 3),
                "pending_acceptances": self.governance.pending_acceptances,
            },
            "recent_anomalies":  self.recent_anomalies[:10],
            "recommendations":   self.recommendations,
        }


# ── Data fetchers ─────────────────────────────────────────────────────────────

def _fetch_transfer_stats(community_id: str) -> TransferStats:
    stats = TransferStats()
    try:
        conn = sqlite3.connect(_SEP_DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT status, target_data_class, target_community FROM sep_transfers WHERE source_community=?",
            (community_id,),
        ).fetchall()
        stats.total = len(rows)
        target_counts: dict[str, int] = {}
        for r in rows:
            s = r["status"] or "ACCEPTED"
            if s == "REJECTED":
                stats.rejected += 1
            else:
                stats.accepted += 1
            dc = r["target_data_class"] or "GENERAL"
            stats.by_data_class[dc] = stats.by_data_class.get(dc, 0) + 1
            tc = r["target_community"] or ""
            if tc:
                target_counts[tc] = target_counts.get(tc, 0) + 1
        stats.top_target_communities = [
            {"community_id": k, "count": v}
            for k, v in sorted(target_counts.items(), key=lambda x: -x[1])[:5]
        ]
    except Exception as exc:  # noqa: BLE001
        log.debug("transfer stats unavailable: %s", exc)
    return stats


def _fetch_peering_stats(community_id: str) -> PeeringStats:
    stats = PeeringStats()
    try:
        conn = sqlite3.connect(_SEP_DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT status, policy FROM sep_peerings
               WHERE initiator_community=? OR target_community=?""",
            (community_id, community_id),
        ).fetchall()
        stats.total = len(rows)
        for r in rows:
            if r["status"] == "ACTIVE":
                stats.active += 1
            elif r["status"] == "REVOKED":
                stats.revoked += 1
            policy = r["policy"] or "REWRAP_ALLOWED"
            stats.by_policy[policy] = stats.by_policy.get(policy, 0) + 1
    except Exception as exc:  # noqa: BLE001
        log.debug("peering stats unavailable: %s", exc)
    return stats


def _fetch_governance_stats(community_id: str) -> GovernanceStats:
    stats = GovernanceStats()
    try:
        conn = sqlite3.connect(_REGISTRY_DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row

        charter_row = conn.execute(
            "SELECT charter_id, version FROM community_charters WHERE community_id=? AND status='ACTIVE' LIMIT 1",
            (community_id,),
        ).fetchone()

        if not charter_row:
            return stats

        stats.charter_active = True
        stats.charter_version = charter_row["version"]
        charter_id = charter_row["charter_id"]

        total_members = conn.execute(
            "SELECT COUNT(*) as c FROM community_members WHERE community_id=? AND status='ACTIVE'",
            (community_id,),
        ).fetchone()["c"]

        accepted = conn.execute(
            "SELECT COUNT(*) as c FROM community_charter_accepts WHERE charter_id=?",
            (charter_id,),
        ).fetchone()["c"]

        stats.pending_acceptances = max(total_members - accepted, 0)
        stats.acceptance_rate = (accepted / total_members) if total_members > 0 else 1.0
    except Exception as exc:  # noqa: BLE001
        log.debug("governance stats unavailable: %s", exc)
    return stats


def _fetch_recent_anomalies(community_id: str) -> list[dict]:
    try:
        from warden.communities.behavioral import list_recent_anomalies
        return list_recent_anomalies(community_id, limit=10)
    except Exception as exc:  # noqa: BLE001
        log.debug("anomaly fetch unavailable: %s", exc)
        return []


# ── Risk scoring ──────────────────────────────────────────────────────────────

def _compute_risk(
    transfers: TransferStats,
    peerings: PeeringStats,
    governance: GovernanceStats,
    anomalies: list[dict],
) -> RiskScore:
    # Transfer rejection rate
    rejection_rate = (
        transfers.rejected / transfers.total if transfers.total > 0 else 0.0
    )

    # Anomaly score: fraction of CRITICAL anomalies in recent window
    critical_count = sum(1 for a in anomalies if a.get("severity") == "CRITICAL")
    anomaly_score = min(critical_count / 10.0, 1.0)

    # Governance gap: 1.0 - acceptance_rate (0 = full compliance)
    governance_gap = 1.0 - governance.acceptance_rate if governance.charter_active else 0.0

    # Weighted overall
    overall = (
        0.40 * rejection_rate
        + 0.35 * anomaly_score
        + 0.25 * governance_gap
    )
    overall = min(overall, 1.0)

    if overall < 0.15:
        label = "SAFE"
    elif overall < 0.35:
        label = "LOW"
    elif overall < 0.55:
        label = "MEDIUM"
    elif overall < 0.75:
        label = "HIGH"
    else:
        label = "CRITICAL"

    return RiskScore(
        overall=overall,
        anomaly_score=anomaly_score,
        transfer_rejection_rate=rejection_rate,
        governance_gap=governance_gap,
        label=label,
    )


def _build_recommendations(risk: RiskScore, governance: GovernanceStats, peerings: PeeringStats) -> list[str]:
    recs: list[str] = []
    if not governance.charter_active:
        recs.append("Publish a Community Charter to establish governance rules and build member trust.")
    elif governance.acceptance_rate < 0.8:
        recs.append(
            f"{governance.pending_acceptances} member(s) have not accepted the active charter — "
            "send reminders or restrict their transfer permissions."
        )
    if risk.transfer_rejection_rate > 0.10:
        recs.append(
            "Transfer rejection rate >10% — review Causal Transfer Guard thresholds "
            "and data pod jurisdiction mappings."
        )
    if risk.anomaly_score > 0.30:
        recs.append(
            "Multiple CRITICAL anomalies detected — investigate off-hours access and "
            "bulk transfer patterns via the Behavioral Analytics tab."
        )
    if peerings.revoked > peerings.active and peerings.total > 0:
        recs.append(
            "More peerins are REVOKED than ACTIVE — review peering lifecycle and "
            "consider re-establishing key partnerships."
        )
    if not recs:
        recs.append("Community posture is healthy. Continue monitoring behavioral baselines weekly.")
    return recs


# ── Main entry point ──────────────────────────────────────────────────────────

def generate_report(community_id: str) -> CommunityIntelReport:
    """Generate a full intelligence report for a community."""
    transfers  = _fetch_transfer_stats(community_id)
    peerings   = _fetch_peering_stats(community_id)
    governance = _fetch_governance_stats(community_id)
    anomalies  = _fetch_recent_anomalies(community_id)
    risk       = _compute_risk(transfers, peerings, governance, anomalies)
    recs       = _build_recommendations(risk, governance, peerings)

    report = CommunityIntelReport(
        community_id=community_id,
        generated_at=datetime.now(UTC).isoformat(),
        risk=risk,
        transfers=transfers,
        peerings=peerings,
        governance=governance,
        recent_anomalies=anomalies,
        recommendations=recs,
    )
    log.info("intel report generated community=%s risk=%s", community_id, risk.label)
    return report
