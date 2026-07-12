"""
warden/marketplace/maestro.py
──────────────────────────────
MAESTRO Threat Detection — specialised security for M2M agentic marketplaces.

Three threat domains (all fail-open — exceptions produce score=0.0, never block):

  1. GoalMisalignmentDetector  — agents deviating from their community's stated goals.
  2. CollusionDetector         — coordinated price manipulation in negotiation pairs.
  3. ModelPoisoningDetector    — statistical outlier detection for imported assets.

MaestroService aggregates all three into a single MaestroReport with a unified
threat level and recommended action.

Integration points:
  • ReputationEngine   — maestro_penalty component (10% weight)
  • AssetImporter      — validate_imported_rule / validate_imported_model before hot-load
  • NegotiationEngine  — analyze_negotiation_pair after accept_offer()
  • EscrowService      — evaluate_agent after confirm_receipt()
  • Prometheus         — warden_maestro_*_detected_total counters
"""
from __future__ import annotations

import json
import logging
import math
import os
import re
import sqlite3
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from warden.config import data_path

log = logging.getLogger("warden.marketplace.maestro")

_DB_PATH       = data_path("warden_marketplace.db", "MARKETPLACE_DB_PATH")
_db_lock       = threading.RLock()
_COLLUSION_TTL = 90 * 86_400   # 90 days in seconds

# ── Schema ────────────────────────────────────────────────────────────────────

_SCHEMA = """
CREATE TABLE IF NOT EXISTS maestro_agent_stats (
    agent_id        TEXT PRIMARY KEY,
    community_id    TEXT NOT NULL DEFAULT '',
    total_trades    INTEGER NOT NULL DEFAULT 0,
    discount_sum    REAL NOT NULL DEFAULT 0.0,
    unverified_buys INTEGER NOT NULL DEFAULT 0,
    total_buys      INTEGER NOT NULL DEFAULT 0,
    dispute_count   INTEGER NOT NULL DEFAULT 0,
    misalignment    REAL NOT NULL DEFAULT 0.0,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS maestro_negotiations (
    pair_key        TEXT NOT NULL,
    agent_a         TEXT NOT NULL,
    agent_b         TEXT NOT NULL,
    rounds          INTEGER NOT NULL DEFAULT 0,
    price_delta_pct REAL NOT NULL DEFAULT 0.0,
    created_at      TEXT NOT NULL,
    PRIMARY KEY (pair_key, created_at)
);
CREATE INDEX IF NOT EXISTS idx_mn_pair ON maestro_negotiations(pair_key);

CREATE TABLE IF NOT EXISTS maestro_asset_baselines (
    community_id    TEXT PRIMARY KEY,
    rule_count      INTEGER NOT NULL DEFAULT 0,
    avg_length      REAL NOT NULL DEFAULT 0.0,
    avg_word_count  REAL NOT NULL DEFAULT 0.0,
    avg_complexity  REAL NOT NULL DEFAULT 0.0,
    std_length      REAL NOT NULL DEFAULT 0.0,
    std_word_count  REAL NOT NULL DEFAULT 0.0,
    std_complexity  REAL NOT NULL DEFAULT 0.0,
    updated_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS maestro_flags (
    flag_id         TEXT PRIMARY KEY,
    agent_id        TEXT NOT NULL,
    flag_type       TEXT NOT NULL,
    score           REAL NOT NULL DEFAULT 0.0,
    details         TEXT NOT NULL DEFAULT '{}',
    created_at      TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_mf_agent ON maestro_flags(agent_id, flag_type);
"""


def _conn(db_path: str = _DB_PATH) -> sqlite3.Connection:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(_SCHEMA)
    return con


# ── Helpers ───────────────────────────────────────────────────────────────────

def _stdev(values: list[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((x - mean) ** 2 for x in values) / (n - 1))


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _rule_features(rule_text: str) -> dict[str, float]:
    """Extract numeric features from a rule/regex text."""
    length     = float(len(rule_text))
    word_count = float(len(rule_text.split()))
    # Complexity = count of special regex metacharacters
    complexity = float(len(re.findall(r'[.*+?^${}()|[\]\\]', rule_text)))
    return {"length": length, "word_count": word_count, "complexity": complexity}


def _redis_client():
    try:
        import redis as _r  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        if url.startswith("memory://"):
            return None
        return _r.from_url(url, decode_responses=True)
    except Exception:
        return None


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class PoisoningReport:
    score:   float
    flagged: bool
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MaestroReport:
    agent_id:           str
    misalignment_score: float
    collusion_flags:    list[str]
    poisoning_risk:     bool
    overall_threat_level: str          # low | medium | high
    recommended_action:   str          # none | monitor | restrict | suspend
    behavioral_flag:    bool = False
    behavioral_dimensions: list[dict] = field(default_factory=list)
    tacit_collusion_scores: dict = field(default_factory=dict)
    generated_at:       str = field(default_factory=lambda: datetime.now(UTC).isoformat())

    def to_dict(self) -> dict:
        return asdict(self)


# ── Goal Misalignment Detector ────────────────────────────────────────────────

class GoalMisalignmentDetector:
    """
    Detects agents whose behaviour deviates from community trading goals.

    Community goals are stored per community_id in Redis (fail-open: defaults
    to the standard set when Redis is unavailable).

    Default goals: fair_pricing, volume_optimisation, risk_minimisation.
    """

    DEFAULT_GOALS = {"fair_pricing", "volume_optimisation", "risk_minimisation"}

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path

    # ── Community goal registry ───────────────────────────────────────────────

    def set_community_goals(self, community_id: str, goals: list[str]) -> None:
        """Persist community trading goals to Redis (fail-open)."""
        try:
            r = _redis_client()
            if r:
                r.setex(
                    f"maestro:goals:{community_id}",
                    86_400 * 365,
                    json.dumps(goals),
                )
        except Exception:
            pass

    def get_community_goals(self, community_id: str) -> set[str]:
        try:
            r = _redis_client()
            if r:
                raw = r.get(f"maestro:goals:{community_id}")
                if raw:
                    return set(json.loads(raw))
        except Exception:
            pass
        return set(self.DEFAULT_GOALS)

    # ── Per-trade stats update ────────────────────────────────────────────────

    def record_trade(
        self,
        agent_id:       str,
        community_id:   str,
        discount_pct:   float,
        seller_verified: bool,
        is_disputed:    bool,
    ) -> None:
        """Update rolling stats for an agent after a trade. Fail-open."""
        try:
            now = datetime.now(UTC).isoformat()
            with _db_lock:
                con = _conn(self.db_path)
                row = con.execute(
                    "SELECT * FROM maestro_agent_stats WHERE agent_id=?", (agent_id,)
                ).fetchone()
                if row:
                    con.execute(
                        """UPDATE maestro_agent_stats SET
                           community_id=?, total_trades=total_trades+1,
                           discount_sum=discount_sum+?,
                           unverified_buys=unverified_buys+?,
                           total_buys=total_buys+1,
                           dispute_count=dispute_count+?,
                           updated_at=?
                           WHERE agent_id=?""",
                        (
                            community_id,
                            abs(discount_pct),
                            0 if seller_verified else 1,
                            1 if is_disputed else 0,
                            now,
                            agent_id,
                        ),
                    )
                else:
                    con.execute(
                        """INSERT INTO maestro_agent_stats
                           (agent_id, community_id, total_trades, discount_sum,
                            unverified_buys, total_buys, dispute_count, misalignment, updated_at)
                           VALUES (?,?,1,?,?,1,?,0.0,?)""",
                        (
                            agent_id,
                            community_id,
                            abs(discount_pct),
                            0 if seller_verified else 1,
                            1 if is_disputed else 0,
                            now,
                        ),
                    )
                con.commit()
                con.close()
        except Exception as exc:
            log.debug("GoalMisalignment.record_trade: %s", exc)

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate_agent(self, agent_id: str) -> float:
        """
        Compute and persist misalignment score for agent_id.
        Returns 0.0–1.0 (higher = more misaligned). Fail-open → 0.0.
        """
        try:
            return self._evaluate(agent_id)
        except Exception as exc:
            log.debug("GoalMisalignment.evaluate_agent fail-open: %s", exc)
            return 0.0

    def _evaluate(self, agent_id: str) -> float:
        with _db_lock:
            con = _conn(self.db_path)
            row = con.execute(
                "SELECT * FROM maestro_agent_stats WHERE agent_id=?", (agent_id,)
            ).fetchone()

        if not row or row["total_trades"] < 3:
            return 0.0

        community_id = row["community_id"]
        goals        = self.get_community_goals(community_id)
        violations   = 0
        max_checks   = 0

        agent_avg_discount = row["discount_sum"] / row["total_trades"]

        with _db_lock:
            con = _conn(self.db_path)
            # Community mean discount
            peer_rows = con.execute(
                "SELECT discount_sum, total_trades FROM maestro_agent_stats WHERE community_id=?",
                (community_id,),
            ).fetchall()
            con.close()

        peer_discounts = [
            r["discount_sum"] / r["total_trades"]
            for r in peer_rows
            if r["total_trades"] >= 3
        ]

        if "fair_pricing" in goals and len(peer_discounts) >= 3:
            max_checks += 1
            comm_mean = _mean(peer_discounts)
            comm_std  = _stdev(peer_discounts) or 0.01
            z = abs(agent_avg_discount - comm_mean) / comm_std
            if z > 2.0:
                violations += 1

        if "risk_minimisation" in goals and row["total_buys"] >= 3:
            max_checks += 1
            unverified_ratio = row["unverified_buys"] / row["total_buys"]
            if unverified_ratio > 0.30:
                violations += 1

        if max_checks == 0:
            return 0.0

        score = violations / max_checks
        try:
            with _db_lock:
                con = _conn(self.db_path)
                con.execute(
                    "UPDATE maestro_agent_stats SET misalignment=?, updated_at=? WHERE agent_id=?",
                    (score, datetime.now(UTC).isoformat(), agent_id),
                )
                con.commit()
                con.close()
        except Exception:
            pass

        if score > 0.0:
            self._emit_counter()
            self._flag_agent(agent_id, "misalignment", score, {"violations": violations})

        return score

    def get_misalignment_score(self, agent_id: str) -> float:
        try:
            with _db_lock:
                con = _conn(self.db_path)
                row = con.execute(
                    "SELECT misalignment FROM maestro_agent_stats WHERE agent_id=?",
                    (agent_id,),
                ).fetchone()
                con.close()
            return float(row["misalignment"]) if row else 0.0
        except Exception:
            return 0.0

    @staticmethod
    def _emit_counter() -> None:
        try:
            from warden.metrics import MAESTRO_MISALIGNMENT_TOTAL  # noqa: PLC0415
            MAESTRO_MISALIGNMENT_TOTAL.inc()
        except Exception:
            pass

    @staticmethod
    def _flag_agent(agent_id: str, flag_type: str, score: float, details: dict) -> None:
        try:
            with _db_lock:
                con = _conn()
                con.execute(
                    """INSERT OR REPLACE INTO maestro_flags
                       (flag_id, agent_id, flag_type, score, details, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        str(uuid.uuid4()),
                        agent_id,
                        flag_type,
                        score,
                        json.dumps(details),
                        datetime.now(UTC).isoformat(),
                    ),
                )
                con.commit()
                con.close()
        except Exception:
            pass


# ── Collusion Detector ────────────────────────────────────────────────────────

class CollusionDetector:
    """
    Detects coordinated price manipulation between negotiation pairs.

    A pair is flagged when they consistently:
      • Accept within < 2 counter-offer rounds, AND
      • Final price is within 5% of initial offer.

    This pattern suggests pre-arranged trades that circumvent price discovery.
    Flags stored in Redis collusion:flagged:{agent_id} (90-day TTL).
    """

    _ROUND_THRESHOLD       = 2
    _PRICE_DELTA_THRESHOLD = 5.0   # percent
    _MIN_OBSERVATIONS      = 3     # min negotiation samples before flagging
    _TACIT_CORR_THRESHOLD  = 0.80  # reference rho0 for the Bayesian correlation test
    _TACIT_POSTERIOR_CONF  = 0.90  # flag when P(rho > rho0 | data) >= this
    _TACIT_MIN_SELLERS     = 3     # minimum sellers needed for market-level scan
    _TACIT_WINDOW          = 100   # last N clearing prices per seller

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path

    def analyze_negotiation_pair(
        self,
        agent_a: str,
        agent_b: str,
        rounds:  int,
        initial_price_usd: float,
        final_price_usd:   float,
    ) -> float:
        """
        Record a negotiation and return current collusion score for the pair.
        Fail-open → 0.0 on any exception.
        """
        try:
            return self._analyze(agent_a, agent_b, rounds, initial_price_usd, final_price_usd)
        except Exception as exc:
            log.debug("CollusionDetector.analyze fail-open: %s", exc)
            return 0.0

    def _analyze(
        self,
        agent_a: str,
        agent_b: str,
        rounds:  int,
        initial_price_usd: float,
        final_price_usd:   float,
    ) -> float:
        pair_key    = "_".join(sorted([agent_a, agent_b]))
        now         = datetime.now(UTC).isoformat()
        delta_pct   = (
            abs(final_price_usd - initial_price_usd) / max(abs(initial_price_usd), 0.01) * 100
        )

        with _db_lock:
            con = _conn(self.db_path)
            con.execute(
                """INSERT INTO maestro_negotiations
                   (pair_key, agent_a, agent_b, rounds, price_delta_pct, created_at)
                   VALUES (?,?,?,?,?,?)""",
                (pair_key, agent_a, agent_b, rounds, delta_pct, now),
            )
            con.commit()
            rows = con.execute(
                "SELECT rounds, price_delta_pct FROM maestro_negotiations WHERE pair_key=? ORDER BY created_at DESC LIMIT 20",
                (pair_key,),
            ).fetchall()
            con.close()

        if len(rows) < self._MIN_OBSERVATIONS:
            return 0.0

        suspicious = sum(
            1 for r in rows
            if r["rounds"] < self._ROUND_THRESHOLD and r["price_delta_pct"] < self._PRICE_DELTA_THRESHOLD
        )
        score = suspicious / len(rows)

        if score >= 0.6:
            self._set_collusion_flag(agent_a)
            self._set_collusion_flag(agent_b)
            self._flag_agent(agent_a, "collusion", score, {"pair": agent_b})
            self._flag_agent(agent_b, "collusion", score, {"pair": agent_a})
            self._emit_counter()

        return score

    def get_collusion_score(self, agent_a: str, agent_b: str) -> float:
        """Return the collusion score for a pair. Fail-open → 0.0."""
        try:
            pair_key = "_".join(sorted([agent_a, agent_b]))
            with _db_lock:
                con = _conn(self.db_path)
                rows = con.execute(
                    "SELECT rounds, price_delta_pct FROM maestro_negotiations WHERE pair_key=? ORDER BY created_at DESC LIMIT 20",
                    (pair_key,),
                ).fetchall()
                con.close()
            if len(rows) < self._MIN_OBSERVATIONS:
                return 0.0
            suspicious = sum(
                1 for r in rows
                if r["rounds"] < self._ROUND_THRESHOLD
                and r["price_delta_pct"] < self._PRICE_DELTA_THRESHOLD
            )
            return suspicious / len(rows)
        except Exception:
            return 0.0

    def is_flagged(self, agent_id: str) -> bool:
        """Check Redis collusion flag. Fail-open → False."""
        try:
            r = _redis_client()
            if r:
                return bool(r.exists(f"collusion:flagged:{agent_id}"))
        except Exception:
            pass
        return False

    def get_collusion_partners(self, agent_id: str) -> list[str]:
        """Return list of agents this agent has been flagged colluding with."""
        try:
            with _db_lock:
                con = _conn(self.db_path)
                rows = con.execute(
                    """SELECT details FROM maestro_flags
                       WHERE agent_id=? AND flag_type='collusion'
                       ORDER BY created_at DESC LIMIT 10""",
                    (agent_id,),
                ).fetchall()
                con.close()
            partners = set()
            for row in rows:
                try:
                    d = json.loads(row["details"])
                    if "pair" in d:
                        partners.add(d["pair"])
                except Exception:
                    pass
            return list(partners)
        except Exception:
            return []

    def scan_market_prices(self) -> dict[str, float]:
        """
        Vertical tacit collusion scan — detect synchronized price movements
        across independent sellers without direct negotiation pairs.

        Reads marketplace_clearing_log, computes pairwise Pearson correlation of
        seller price series. High correlation among non-paired sellers indicates
        algorithmic price synchronization (vertical tacit collusion).

        Returns {seller_agent_id: tacit_collusion_score (0.0–1.0)}.
        Fail-open: exceptions return {}.
        """
        try:
            return self._scan_market_prices()
        except Exception as exc:
            log.debug("CollusionDetector.scan_market_prices fail-open: %s", exc)
            return {}

    def _scan_market_prices(self) -> dict[str, float]:
        with _db_lock:
            con = _conn(self.db_path)
            rows = con.execute(
                """SELECT seller_agent_id, seller_net_usd, cleared_at
                   FROM marketplace_clearing_log
                   ORDER BY cleared_at DESC
                   LIMIT ?""",
                (self._TACIT_WINDOW * 20,),
            ).fetchall()
            con.close()

        from collections import defaultdict
        seller_prices: dict[str, list[float]] = defaultdict(list)
        for row in rows:
            if len(seller_prices[row["seller_agent_id"]]) < self._TACIT_WINDOW:
                seller_prices[row["seller_agent_id"]].append(row["seller_net_usd"])

        eligible = {s: p for s, p in seller_prices.items() if len(p) >= 5}
        if len(eligible) < self._TACIT_MIN_SELLERS:
            return {}

        def _pearson(a: list[float], b: list[float]) -> float:
            n = min(len(a), len(b))
            if n < 4:
                return 0.0
            xs, ys = a[:n], b[:n]
            mean_x = sum(xs) / n
            mean_y = sum(ys) / n
            num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=False))
            denom_x = sum((x - mean_x) ** 2 for x in xs) ** 0.5
            denom_y = sum((y - mean_y) ** 2 for y in ys) ** 0.5
            if denom_x == 0 or denom_y == 0:
                return 0.0
            return num / (denom_x * denom_y)

        from warden.marketplace.bayesian_stats import posterior_p_correlation_exceeds

        sellers = list(eligible.keys())
        high_corr_counts: dict[str, int] = dict.fromkeys(sellers, 0)

        for i in range(len(sellers)):
            for j in range(i + 1, len(sellers)):
                pair_a, pair_b = eligible[sellers[i]], eligible[sellers[j]]
                corr = abs(_pearson(pair_a, pair_b))
                n = min(len(pair_a), len(pair_b))
                # Bayesian correlation test (Fisher-z + Jeffreys-equivalent prior):
                # flag on posterior confidence the *true* correlation exceeds the
                # reference, not just the sample point estimate — thin-data
                # samples (n close to the minimum) need a higher r to reach the
                # same posterior confidence, cutting false flags on 3-4 samples.
                p_exceeds = posterior_p_correlation_exceeds(corr, n, self._TACIT_CORR_THRESHOLD)
                if p_exceeds >= self._TACIT_POSTERIOR_CONF:
                    high_corr_counts[sellers[i]] += 1
                    high_corr_counts[sellers[j]] += 1

        scores: dict[str, float] = {}
        max_peers = len(sellers) - 1
        for seller, count in high_corr_counts.items():
            score = round(count / max_peers, 3) if max_peers > 0 else 0.0
            scores[seller] = score
            if score >= 0.5:
                self._set_collusion_flag(seller)
                self._flag_agent(seller, "tacit_collusion", score, {
                    "pattern": "vertical_price_sync",
                    "correlated_peers": count,
                })

        return scores

    def _set_collusion_flag(self, agent_id: str) -> None:
        try:
            r = _redis_client()
            if r:
                r.setex(f"collusion:flagged:{agent_id}", _COLLUSION_TTL, "1")
        except Exception:
            pass

    @staticmethod
    def _emit_counter() -> None:
        try:
            from warden.metrics import MAESTRO_COLLUSION_TOTAL  # noqa: PLC0415
            MAESTRO_COLLUSION_TOTAL.inc()
        except Exception:
            pass

    @staticmethod
    def _flag_agent(agent_id: str, flag_type: str, score: float, details: dict) -> None:
        GoalMisalignmentDetector._flag_agent(agent_id, flag_type, score, details)


# ── Model Poisoning Detector ──────────────────────────────────────────────────

class ModelPoisoningDetector:
    """
    Detects statistical outliers in imported rules and models.

    Rule features: text length, word count, regex complexity score.
    A rule is flagged if it deviates > 3σ on ANY feature from the community
    baseline (computed from all previously accepted rules in that community).
    """

    _SIGMA_THRESHOLD = 3.0

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path

    # ── Rule validation ───────────────────────────────────────────────────────

    def validate_imported_rule(
        self,
        rule_text:    str,
        community_id: str,
    ) -> PoisoningReport:
        """Validate a rule text against the community baseline. Fail-open."""
        try:
            return self._validate_rule(rule_text, community_id)
        except Exception as exc:
            log.debug("ModelPoisoningDetector.validate_rule fail-open: %s", exc)
            return PoisoningReport(score=0.0, flagged=False, reasons=["check_skipped"])

    def _validate_rule(self, rule_text: str, community_id: str) -> PoisoningReport:
        baseline = self._get_or_build_baseline(community_id)
        if not baseline or baseline.get("rule_count", 0) < 5:
            # Not enough data for meaningful comparison
            return PoisoningReport(score=0.0, flagged=False, reasons=["insufficient_baseline"])

        features  = _rule_features(rule_text)
        reasons:  list[str] = []
        max_z     = 0.0

        for feat, value in features.items():
            avg_key = f"avg_{feat}"
            std_key = f"std_{feat}"
            avg  = float(baseline.get(avg_key, 0.0))
            std  = float(baseline.get(std_key, 0.0)) or 0.01
            z    = abs(value - avg) / std
            max_z = max(max_z, z)
            if z > self._SIGMA_THRESHOLD:
                reasons.append(f"{feat}_outlier_z{z:.1f}")

        flagged = len(reasons) > 0
        score   = min(1.0, max_z / (self._SIGMA_THRESHOLD * 2))

        if flagged:
            self._emit_counter()
            log.warning(
                "MAESTRO: rule poisoning flag community=%s reasons=%s score=%.2f",
                community_id, reasons, score,
            )

        return PoisoningReport(score=score, flagged=flagged, reasons=reasons)

    # ── Model (OSI) validation ────────────────────────────────────────────────

    def validate_imported_model(
        self,
        model_osi:    dict,
        community_id: str,
    ) -> PoisoningReport:
        """
        Validate a semantic model OSI dict against the community baseline.
        Uses metric count and dimension count as stability proxies.
        Fail-open.
        """
        try:
            return self._validate_model(model_osi, community_id)
        except Exception as exc:
            log.debug("ModelPoisoningDetector.validate_model fail-open: %s", exc)
            return PoisoningReport(score=0.0, flagged=False, reasons=["check_skipped"])

    def _validate_model(self, model_osi: dict, community_id: str) -> PoisoningReport:
        metric_count = len(model_osi.get("metrics", []))
        dim_count    = len(model_osi.get("dimensions", []))
        # Express as a synthetic "rule" for baseline comparison
        pseudo_text  = " ".join(["metric"] * metric_count + ["dimension"] * dim_count)
        return self._validate_rule(pseudo_text, community_id)

    # ── Baseline management ───────────────────────────────────────────────────

    def _get_or_build_baseline(self, community_id: str) -> dict:
        with _db_lock:
            con = _conn(self.db_path)
            row = con.execute(
                "SELECT * FROM maestro_asset_baselines WHERE community_id=?",
                (community_id,),
            ).fetchone()
            con.close()
        if row:
            return dict(row)
        return self._build_baseline(community_id)

    def _build_baseline(self, community_id: str) -> dict:
        """Build baseline from active rules in marketplace_listings for community."""
        try:
            with _db_lock:
                con = _conn(self.db_path)
                rows = con.execute(
                    """SELECT content FROM marketplace_listings
                       WHERE community_id=? AND status='active' AND asset_type IN ('rule','detection_rule')
                       LIMIT 200""",
                    (community_id,),
                ).fetchall()
                con.close()
        except Exception:
            return {}

        if len(rows) < 5:
            return {}

        all_features: dict[str, list[float]] = {
            "length": [], "word_count": [], "complexity": [],
        }
        for row in rows:
            content = row["content"] if isinstance(row, sqlite3.Row) else row[0]
            if content:
                feats = _rule_features(str(content))
                for k, v in feats.items():
                    all_features[k].append(v)

        now      = datetime.now(UTC).isoformat()
        baseline = {
            "community_id":  community_id,
            "rule_count":    len(rows),
            "avg_length":    _mean(all_features["length"]),
            "avg_word_count": _mean(all_features["word_count"]),
            "avg_complexity": _mean(all_features["complexity"]),
            "std_length":    _stdev(all_features["length"]),
            "std_word_count": _stdev(all_features["word_count"]),
            "std_complexity": _stdev(all_features["complexity"]),
            "updated_at":    now,
        }
        try:
            with _db_lock:
                con = _conn(self.db_path)
                con.execute(
                    """INSERT OR REPLACE INTO maestro_asset_baselines
                       (community_id, rule_count, avg_length, avg_word_count, avg_complexity,
                        std_length, std_word_count, std_complexity, updated_at)
                       VALUES (:community_id,:rule_count,:avg_length,:avg_word_count,:avg_complexity,
                               :std_length,:std_word_count,:std_complexity,:updated_at)""",
                    baseline,
                )
                con.commit()
                con.close()
        except Exception:
            pass

        return baseline

    def update_baseline_from_rule(self, rule_text: str, community_id: str) -> None:
        """Incrementally update baseline after a clean rule is accepted. Fail-open."""
        try:
            baseline = self._get_or_build_baseline(community_id)
            feats    = _rule_features(rule_text)
            n        = max(1, baseline.get("rule_count", 0))
            for feat in ("length", "word_count", "complexity"):
                avg_key = f"avg_{feat}"
                old_avg = float(baseline.get(avg_key, 0.0))
                new_avg = (old_avg * n + feats[feat]) / (n + 1)
                baseline[avg_key] = new_avg
            baseline["rule_count"] = n + 1
            baseline["updated_at"] = datetime.now(UTC).isoformat()
            with _db_lock:
                con = _conn(self.db_path)
                con.execute(
                    """INSERT OR REPLACE INTO maestro_asset_baselines
                       (community_id, rule_count, avg_length, avg_word_count, avg_complexity,
                        std_length, std_word_count, std_complexity, updated_at)
                       VALUES (:community_id,:rule_count,:avg_length,:avg_word_count,:avg_complexity,
                               :std_length,:std_word_count,:std_complexity,:updated_at)""",
                    baseline,
                )
                con.commit()
                con.close()
        except Exception:
            pass

    @staticmethod
    def _emit_counter() -> None:
        try:
            from warden.metrics import MAESTRO_POISONING_TOTAL  # noqa: PLC0415
            MAESTRO_POISONING_TOTAL.inc()
        except Exception:
            pass


# ── Behavioral Anomaly Detector (trading patterns) ───────────────────────────

@dataclass
class TradingAnomalyReport:
    agent_id:      str
    flagged:       bool
    dimensions:    list[dict] = field(default_factory=list)  # [{name, z_score, severity}]


class BehavioralAnomalyDetector:
    """
    Z-score anomaly detection for marketplace trading patterns.

    Tracks 4 dimensions per agent over a 30-day rolling window:
      - trade_frequency   (trades/day)
      - avg_trade_value   (USD)
      - negotiation_rounds (rounds per negotiation)
      - dispute_rate      (disputes / total_trades)

    Z-score ≥ 3.0 → CRITICAL flag; ≥ 2.0 → ELEVATED.
    Reuses warden.communities.behavioral.detect_anomaly where available.
    """

    _Z_CRITICAL = 3.0
    _Z_ELEVATED  = 2.0

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path = db_path

    def evaluate(self, agent_id: str) -> TradingAnomalyReport:
        """Evaluate trading-pattern anomalies for *agent_id*. Fail-open."""
        try:
            return self._run(agent_id)
        except Exception as exc:
            log.debug("BehavioralAnomalyDetector: fail-open agent=%s: %s", agent_id, exc)
            return TradingAnomalyReport(agent_id=agent_id, flagged=False)

    def _run(self, agent_id: str) -> TradingAnomalyReport:
        stats = self._load_stats(agent_id)
        if not stats:
            return TradingAnomalyReport(agent_id=agent_id, flagged=False)

        community_id = stats.get("community_id", "")
        total_trades = max(1, stats.get("total_trades", 0))

        # Derive current dimension values
        days_active = max(1, self._days_since_first_trade(agent_id))
        current_values = {
            "trade_frequency":    total_trades / days_active,
            "avg_trade_value":    stats.get("discount_sum", 0.0) / total_trades,
            "negotiation_rounds": stats.get("round_count_sum", 0.0) / total_trades,
            "dispute_rate":       stats.get("dispute_count", 0) / total_trades,
        }

        dimensions: list[dict] = []
        flagged = False

        for dim, current in current_values.items():
            z = self._z_score(dim, current, community_id)
            if z is None:
                continue
            severity = (
                "CRITICAL" if abs(z) >= self._Z_CRITICAL
                else "ELEVATED" if abs(z) >= self._Z_ELEVATED
                else "NORMAL"
            )
            if severity != "NORMAL":
                flagged = True
            dimensions.append({"name": dim, "z_score": round(z, 3), "severity": severity})

        return TradingAnomalyReport(agent_id=agent_id, flagged=flagged, dimensions=dimensions)

    def _load_stats(self, agent_id: str) -> dict | None:
        try:
            with _db_lock:
                con = _conn(self.db_path)
                row = con.execute(
                    "SELECT * FROM maestro_agent_stats WHERE agent_id=?", (agent_id,)
                ).fetchone()
                con.close()
            return dict(row) if row else None
        except Exception:
            return None

    def _days_since_first_trade(self, agent_id: str) -> float:
        try:
            with _db_lock:
                con = _conn(self.db_path)
                row = con.execute(
                    "SELECT MIN(created_at) FROM maestro_flags WHERE agent_id=?",
                    (agent_id,),
                ).fetchone()
                con.close()
            if row and row[0]:
                then = datetime.fromisoformat(row[0])
                if then.tzinfo is None:
                    then = then.replace(tzinfo=UTC)
                return max(1.0, (datetime.now(UTC) - then).total_seconds() / 86_400)
        except Exception:
            pass
        return 1.0

    def _z_score(self, dim: str, value: float, community_id: str) -> float | None:
        """Try warden.communities.behavioral; fall back to community stats."""
        try:
            from warden.communities.behavioral import detect_anomaly
            result = detect_anomaly(community_id, dim, value)
            return getattr(result, "z_score", None)
        except Exception:
            pass
        # Simple fallback: look at all agents in this community
        try:
            with _db_lock:
                con = _conn(self.db_path)
                rows = con.execute(
                    "SELECT total_trades, discount_sum FROM maestro_agent_stats WHERE community_id=?",
                    (community_id,),
                ).fetchall()
                con.close()
            values = [float(r["total_trades"]) for r in rows if r["total_trades"] > 0]
            if len(values) < 3:
                return None
            mean = _mean(values)
            std = _stdev(values)
            return (value - mean) / std if std > 0 else 0.0
        except Exception:
            return None


# ── MaestroService ────────────────────────────────────────────────────────────

class MaestroService:
    """
    Aggregates all three MAESTRO detectors into a single MaestroReport.

    Threat levels:
      low     — all scores < 0.3 and no collusion flag
      medium  — any score ≥ 0.3
      high    — any score ≥ 0.7 OR collusion flag active
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self.db_path          = db_path
        self.misalignment     = GoalMisalignmentDetector(db_path)
        self.collusion        = CollusionDetector(db_path)
        self.poisoning        = ModelPoisoningDetector(db_path)
        self.trading_anomaly  = BehavioralAnomalyDetector(db_path)

    def run_full_audit(self, agent_id: str) -> MaestroReport:
        """Run all detectors and return a combined MaestroReport. Fail-open."""
        mis_score       = 0.0
        collusion_flags : list[str] = []
        poisoning_risk  = False

        try:
            mis_score = self.misalignment.evaluate_agent(agent_id)
        except Exception as exc:
            log.debug("MaestroService: misalignment fail-open: %s", exc)

        try:
            collusion_flags = self.collusion.get_collusion_partners(agent_id)
            if not collusion_flags and self.collusion.is_flagged(agent_id):
                collusion_flags = ["unknown_partner"]
        except Exception as exc:
            log.debug("MaestroService: collusion fail-open: %s", exc)

        # Trading pattern anomaly detection (Phase 4-9)
        anomaly = self.trading_anomaly.evaluate(agent_id)

        # Determine threat level
        collusion_active = bool(collusion_flags)
        threat_level, recommended_action = self._classify(
            mis_score, collusion_active, poisoning_risk,
        )

        return MaestroReport(
            agent_id=agent_id,
            misalignment_score=round(mis_score, 4),
            collusion_flags=collusion_flags,
            poisoning_risk=poisoning_risk,
            overall_threat_level=threat_level,
            recommended_action=recommended_action,
            behavioral_flag=anomaly.flagged,
            behavioral_dimensions=anomaly.dimensions,
        )

    def scan_market_tacit_collusion(self) -> dict[str, float]:
        """
        Market-wide vertical tacit collusion scan.

        Delegates to CollusionDetector.scan_market_prices(). Returns per-seller
        tacit collusion scores. Fail-open: exceptions return {}.
        """
        try:
            return self.collusion.scan_market_prices()
        except Exception as exc:
            log.debug("MaestroService.scan_market_tacit_collusion fail-open: %s", exc)
            return {}

    @staticmethod
    def _classify(
        mis_score: float,
        collusion_active: bool,
        poisoning_risk: bool,
    ) -> tuple[str, str]:
        poisoning_score = 1.0 if poisoning_risk else 0.0
        max_score       = max(mis_score, poisoning_score)

        if max_score >= 0.70 or collusion_active:
            return "high",   "restrict"
        if max_score >= 0.30:
            return "medium", "monitor"
        return "low",    "none"

    def get_maestro_penalty(self, agent_id: str) -> float:
        """
        Compute the MAESTRO penalty component used by ReputationEngine.
        Returns 0.0–1.0. Called per reputation calculation; fail-open → 0.0.
        """
        try:
            mis_score      = self.misalignment.get_misalignment_score(agent_id)
            collusion_flag = 1.0 if self.collusion.is_flagged(agent_id) else 0.0
            return min(1.0, max(mis_score, collusion_flag))
        except Exception:
            return 0.0

    # ── Admin queries ─────────────────────────────────────────────────────────

    def list_flagged_agents(self, limit: int = 100) -> list[dict]:
        """Return all agents with active MAESTRO flags, newest first."""
        try:
            with _db_lock:
                con = _conn(self.db_path)
                rows = con.execute(
                    """SELECT agent_id, flag_type, score, details, created_at
                       FROM maestro_flags
                       ORDER BY created_at DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
                con.close()
            return [dict(r) for r in rows]
        except Exception:
            return []

    def get_historical_scores(self, agent_id: str) -> list[dict]:
        """Return misalignment history from flags table."""
        try:
            with _db_lock:
                con = _conn(self.db_path)
                rows = con.execute(
                    """SELECT score, created_at FROM maestro_flags
                       WHERE agent_id=? AND flag_type='misalignment'
                       ORDER BY created_at ASC LIMIT 100""",
                    (agent_id,),
                ).fetchall()
                con.close()
            return [{"score": r["score"], "ts": r["created_at"]} for r in rows]
        except Exception:
            return []


# ── Module-level singleton ────────────────────────────────────────────────────

_service: MaestroService | None = None
_service_lock = threading.Lock()


def get_maestro_service(db_path: str = _DB_PATH) -> MaestroService:
    """Return the process-level MaestroService singleton."""
    global _service
    with _service_lock:
        if _service is None:
            _service = MaestroService(db_path)
    return _service
