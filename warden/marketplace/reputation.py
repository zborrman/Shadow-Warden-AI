"""
warden/marketplace/reputation.py
──────────────────────────────────
ReputationEngine — computes trust scores for marketplace agents based on
their trading history.

Score formula
─────────────
  score = completed_rate * 0.6 + volume_factor * 0.25 + dispute_penalty * 0.15

  completed_rate  = completed / max(total, 1)          [0.0–1.0]
  volume_factor   = min(completed / 10, 1.0)           [0.0–1.0 cap at 10 trades]
  dispute_penalty = max(0, 1 - disputes / max(total,1)) [1.0 = no disputes]

Score bands: UNKNOWN (<3 trades), LOW (<0.4), MEDIUM (<0.7), HIGH (>=0.7)
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

log = logging.getLogger("warden.marketplace.reputation")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")

_MIN_TRADES_FOR_SCORE = 3   # below this: UNKNOWN band


@dataclass
class ReputationScore:
    agent_id:       str
    score:          float
    band:           str          # UNKNOWN | LOW | MEDIUM | HIGH
    total_trades:   int
    completed:      int
    disputes:       int
    as_seller:      int
    as_buyer:       int

    def to_dict(self) -> dict:
        return {
            "agent_id":    self.agent_id,
            "score":       round(self.score, 4),
            "band":        self.band,
            "total_trades": self.total_trades,
            "completed":   self.completed,
            "disputes":    self.disputes,
            "as_seller":   self.as_seller,
            "as_buyer":    self.as_buyer,
        }


class ReputationEngine:
    """Stateless score calculator — instantiate per call or reuse freely."""

    def get_score(
        self,
        agent_id: str,
        db_path: str = _DB_PATH,
    ) -> ReputationScore:
        """Compute and return the current reputation score for *agent_id*."""
        stats = self._fetch_stats(agent_id, db_path)
        total     = stats["total"]
        completed = stats["completed"]
        disputes  = stats["disputes"]
        as_seller = stats["as_seller"]
        as_buyer  = stats["as_buyer"]

        if total < _MIN_TRADES_FOR_SCORE:
            return ReputationScore(
                agent_id=agent_id,
                score=0.5,
                band="UNKNOWN",
                total_trades=total,
                completed=completed,
                disputes=disputes,
                as_seller=as_seller,
                as_buyer=as_buyer,
            )

        completed_rate  = completed / total
        volume_factor   = min(completed / 10.0, 1.0)
        dispute_penalty = max(0.0, 1.0 - disputes / total)

        score = (
            completed_rate  * 0.60
            + volume_factor   * 0.25
            + dispute_penalty * 0.15
        )
        score = max(0.0, min(1.0, score))

        if score >= 0.70:
            band = "HIGH"
        elif score >= 0.40:
            band = "MEDIUM"
        else:
            band = "LOW"

        return ReputationScore(
            agent_id=agent_id,
            score=score,
            band=band,
            total_trades=total,
            completed=completed,
            disputes=disputes,
            as_seller=as_seller,
            as_buyer=as_buyer,
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
                "total":     int(row["total"] or 0),
                "completed": int(row["completed"] or 0),
                "disputes":  int(row["disputes"] or 0),
                "as_seller": int(row["as_seller"] or 0),
                "as_buyer":  int(row["as_buyer"] or 0),
            }
        except Exception as exc:
            log.debug("ReputationEngine stats fetch failed for %s: %s", agent_id, exc)
            return {"total": 0, "completed": 0, "disputes": 0, "as_seller": 0, "as_buyer": 0}
