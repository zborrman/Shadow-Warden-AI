"""
warden/marketplace/reputation.py
──────────────────────────────────
ReputationEngine — 6-component trust score for marketplace agents.

Score formula (v3 — MAESTRO integrated)
────────────────────────────────────────
  score = completed_rate  * 0.45
        + volume_factor   * 0.12
        + dispute_penalty * 0.08
        + trust_rank      * 0.15
        + sybil_component * 0.10
        + maestro_factor  * 0.10

  completed_rate  = completed / max(total, 1)
  volume_factor   = min(completed / 10, 1.0)      [caps at 10 trades]
  dispute_penalty = max(0, 1 - disputes / max(total,1))
  trust_rank      = TrustGraph.get_trust_score()  [0.0–1.0]
  sybil_component = 1.0 - SybilGuard.compute_sybil_penalty()
  maestro_factor  = 1.0 - maestro_penalty          [MAESTRO threat penalty]

  maestro_penalty = max(misalignment_score, collusion_score, poisoning_flag ? 1.0 : 0.0)

Post-trade side-effects (called externally after confirmed purchase):
  • TrustGraph.update_graph(purchase)
  • If sybil_penalty > 0.5 → suspend agent (capabilities → [])

Score bands: UNKNOWN (<3 trades), LOW (<0.4), MEDIUM (<0.7), HIGH (>=0.7)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field

log = logging.getLogger("warden.marketplace.reputation")

_DB_PATH             = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_MIN_TRADES_FOR_SCORE = 3


@dataclass
class ReputationScore:
    agent_id:         str
    score:            float
    band:             str           # UNKNOWN | LOW | MEDIUM | HIGH
    total_trades:     int
    completed:        int
    disputes:         int
    as_seller:        int
    as_buyer:         int
    trust_rank:       float = 0.5
    sybil_penalty:    float = 0.0
    sybil_flagged:    bool  = False
    maestro_penalty:  float = 0.0
    components:       dict  = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "agent_id":        self.agent_id,
            "score":           round(self.score, 4),
            "band":            self.band,
            "total_trades":    self.total_trades,
            "completed":       self.completed,
            "disputes":        self.disputes,
            "as_seller":       self.as_seller,
            "as_buyer":        self.as_buyer,
            "trust_rank":      round(self.trust_rank, 4),
            "sybil_penalty":   round(self.sybil_penalty, 4),
            "sybil_flagged":   self.sybil_flagged,
            "maestro_penalty": round(self.maestro_penalty, 4),
            "components":      self.components,
        }


class ReputationEngine:
    """Stateless score calculator — instantiate per call or reuse freely."""

    def get_score(
        self,
        agent_id:      str,
        db_path:       str  = _DB_PATH,
        trust_graph    = None,       # TrustGraph instance (optional)
        sybil_guard    = None,       # SybilGuard instance (optional)
        maestro_service= None,       # MaestroService instance (optional)
    ) -> ReputationScore:
        stats     = self._fetch_stats(agent_id, db_path)
        total     = stats["total"]
        completed = stats["completed"]
        disputes  = stats["disputes"]
        as_seller = stats["as_seller"]
        as_buyer  = stats["as_buyer"]

        # Trust graph + Sybil + MAESTRO signals (all fail-open)
        trust_rank     = 0.5
        sybil_penalty  = 0.0
        sybil_flagged  = False
        maestro_penalty = 0.0
        try:
            if trust_graph is not None:
                trust_rank = trust_graph.get_trust_score(agent_id)
        except Exception:
            pass
        try:
            if sybil_guard is not None:
                sybil_penalty = sybil_guard.compute_sybil_penalty(agent_id, db_path)
                sybil_flagged = sybil_guard.is_flagged(agent_id)
        except Exception:
            pass
        try:
            if maestro_service is not None:
                maestro_penalty = maestro_service.get_maestro_penalty(agent_id)
            else:
                # Lazy import so reputation works without MAESTRO in tests
                from warden.marketplace.maestro import get_maestro_service as _gms  # noqa: PLC0415
                maestro_penalty = _gms(db_path).get_maestro_penalty(agent_id)
        except Exception:
            pass

        if total < _MIN_TRADES_FOR_SCORE:
            return ReputationScore(
                agent_id=agent_id, score=0.5, band="UNKNOWN",
                total_trades=total, completed=completed, disputes=disputes,
                as_seller=as_seller, as_buyer=as_buyer,
                trust_rank=trust_rank, sybil_penalty=sybil_penalty,
                sybil_flagged=sybil_flagged, maestro_penalty=maestro_penalty,
            )

        completed_rate  = completed / total
        volume_factor   = min(completed / 10.0, 1.0)
        dispute_penalty = max(0.0, 1.0 - disputes / total)
        sybil_component = 1.0 - sybil_penalty
        maestro_factor  = 1.0 - maestro_penalty

        score = (
            completed_rate  * 0.45
            + volume_factor   * 0.12
            + dispute_penalty * 0.08
            + trust_rank      * 0.15
            + sybil_component * 0.10
            + maestro_factor  * 0.10
        )
        score = max(0.0, min(1.0, score))

        band = "HIGH" if score >= 0.70 else ("MEDIUM" if score >= 0.40 else "LOW")

        return ReputationScore(
            agent_id=agent_id,
            score=score,
            band=band,
            total_trades=total,
            completed=completed,
            disputes=disputes,
            as_seller=as_seller,
            as_buyer=as_buyer,
            trust_rank=trust_rank,
            sybil_penalty=sybil_penalty,
            sybil_flagged=sybil_flagged,
            maestro_penalty=maestro_penalty,
            components={
                "completed_rate":  round(completed_rate, 4),
                "volume_factor":   round(volume_factor, 4),
                "dispute_penalty": round(dispute_penalty, 4),
                "trust_rank":      round(trust_rank, 4),
                "sybil_component": round(sybil_component, 4),
                "maestro_factor":  round(maestro_factor, 4),
            },
        )

    def _fetch_stats(self, agent_id: str, db_path: str) -> dict:
        try:
            import sqlite3
            con = sqlite3.connect(db_path)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA journal_mode=WAL")
            row = con.execute(
                """
                SELECT
                  COUNT(*)                                               AS total,
                  SUM(CASE WHEN status='completed' THEN 1 ELSE 0 END)  AS completed,
                  SUM(CASE WHEN status='disputed'  THEN 1 ELSE 0 END)  AS disputes,
                  SUM(CASE WHEN seller_agent=?     THEN 1 ELSE 0 END)  AS as_seller,
                  SUM(CASE WHEN buyer_agent=?      THEN 1 ELSE 0 END)  AS as_buyer
                FROM marketplace_purchases
                WHERE buyer_agent=? OR seller_agent=?
                """,
                (agent_id, agent_id, agent_id, agent_id),
            ).fetchone()
            con.close()
            return {
                "total":     int(row["total"]     or 0),
                "completed": int(row["completed"] or 0),
                "disputes":  int(row["disputes"]  or 0),
                "as_seller": int(row["as_seller"] or 0),
                "as_buyer":  int(row["as_buyer"]  or 0),
            }
        except Exception as exc:
            log.debug("ReputationEngine stats fetch failed for %s: %s", agent_id, exc)
            return {"total": 0, "completed": 0, "disputes": 0, "as_seller": 0, "as_buyer": 0}
