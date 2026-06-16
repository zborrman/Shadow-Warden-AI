"""
warden/marketplace/governance.py
──────────────────────────────────
GovernanceService — Community DAO governance for Marketplace disputes and policy.

Proposal lifecycle:  active → passed | rejected | expired → executed

Vote weight = TrustRank × 100, minimum 1.
Quorum     = max(2, ceil(15% × community member count)).
Expiry     = DAO_PROPOSAL_TTL_HOURS (default 72 h).
"""
from __future__ import annotations

import json
import logging
import math
import os
import sqlite3
import threading
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta

log = logging.getLogger("warden.marketplace.governance")

_DB_PATH = os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
_db_lock = threading.RLock()
_PROPOSAL_TTL_HOURS = int(os.getenv("DAO_PROPOSAL_TTL_HOURS", "72"))
_QUORUM_PCT = float(os.getenv("DAO_QUORUM_PCT", "0.15"))
_DAO_ENABLED = os.getenv("DAO_GOVERNANCE_ENABLED", "false").lower() == "true"

PROPOSAL_TYPES = {"dispute_resolution", "parameter_change", "agent_block"}


def _ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript("""
        CREATE TABLE IF NOT EXISTS dao_proposals (
            proposal_id   TEXT PRIMARY KEY,
            community_id  TEXT NOT NULL,
            proposer_id   TEXT NOT NULL,
            title         TEXT NOT NULL,
            description   TEXT NOT NULL DEFAULT '',
            proposal_type TEXT NOT NULL,
            target_id     TEXT NOT NULL DEFAULT '',
            options       TEXT NOT NULL DEFAULT '["yes","no"]',
            status        TEXT NOT NULL DEFAULT 'active',
            created_at    TEXT NOT NULL,
            expires_at    TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_dao_community ON dao_proposals(community_id);
        CREATE INDEX IF NOT EXISTS idx_dao_status    ON dao_proposals(status);

        CREATE TABLE IF NOT EXISTS dao_votes (
            vote_id     TEXT PRIMARY KEY,
            proposal_id TEXT NOT NULL,
            voter_id    TEXT NOT NULL,
            choice      INTEGER NOT NULL DEFAULT 0,
            weight      REAL    NOT NULL DEFAULT 1.0,
            created_at  TEXT    NOT NULL,
            UNIQUE(proposal_id, voter_id)
        );
        CREATE INDEX IF NOT EXISTS idx_vote_proposal ON dao_votes(proposal_id);
    """)


@contextmanager
def _conn(db_path: str = _DB_PATH) -> Generator[sqlite3.Connection, None, None]:
    con = sqlite3.connect(db_path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    _ensure_schema(con)
    try:
        yield con
        con.commit()
    finally:
        con.close()


@dataclass
class Proposal:
    proposal_id:   str
    community_id:  str
    proposer_id:   str
    title:         str
    description:   str
    proposal_type: str
    target_id:     str
    options:       list[str]
    status:        str
    created_at:    str
    expires_at:    str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["options"] = self.options
        return d

    def is_expired(self) -> bool:
        try:
            exp = datetime.fromisoformat(self.expires_at)
            return datetime.now(UTC) > exp
        except Exception:
            return False


@dataclass
class Vote:
    vote_id:     str
    proposal_id: str
    voter_id:    str
    choice:      int
    weight:      float
    created_at:  str

    def to_dict(self) -> dict:
        return asdict(self)


def _row_to_proposal(row: sqlite3.Row) -> Proposal:
    opts = row["options"]
    if isinstance(opts, str):
        try:
            opts = json.loads(opts)
        except Exception:
            opts = [opts]
    return Proposal(
        proposal_id=row["proposal_id"],
        community_id=row["community_id"],
        proposer_id=row["proposer_id"],
        title=row["title"],
        description=row["description"],
        proposal_type=row["proposal_type"],
        target_id=row["target_id"],
        options=opts,
        status=row["status"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
    )


class GovernanceService:
    """
    Community DAO Governance.

    Three proposal types:
      dispute_resolution — DAO votes to release an escrow to buyer or seller.
      parameter_change   — DAO votes to update a marketplace parameter in Redis.
      agent_block        — DAO votes to revoke all capabilities from an agent.
    """

    def create_proposal(
        self,
        community_id: str,
        proposer_id: str,
        proposal_type: str,
        target_id: str,
        title: str,
        description: str = "",
        options: list[str] | None = None,
        db_path: str = _DB_PATH,
    ) -> Proposal:
        if proposal_type not in PROPOSAL_TYPES:
            raise ValueError(
                f"Unknown proposal_type '{proposal_type}'. Must be one of {sorted(PROPOSAL_TYPES)}."
            )

        if options is None:
            if proposal_type == "dispute_resolution":
                options = ["release_to_buyer", "release_to_seller"]
            elif proposal_type == "agent_block":
                options = ["block_agent", "keep_agent"]
            else:
                options = ["approve", "reject"]

        proposal_id = f"PROP-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(UTC).isoformat()
        expires = (datetime.now(UTC) + timedelta(hours=_PROPOSAL_TTL_HOURS)).isoformat()

        p = Proposal(
            proposal_id=proposal_id,
            community_id=community_id,
            proposer_id=proposer_id,
            title=title,
            description=description,
            proposal_type=proposal_type,
            target_id=target_id,
            options=options,
            status="active",
            created_at=now,
            expires_at=expires,
        )
        with _db_lock, _conn(db_path) as con:
            con.execute(
                """INSERT INTO dao_proposals
                   (proposal_id, community_id, proposer_id, title, description,
                    proposal_type, target_id, options, status, created_at, expires_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    p.proposal_id, p.community_id, p.proposer_id, p.title, p.description,
                    p.proposal_type, p.target_id, json.dumps(p.options), p.status,
                    p.created_at, p.expires_at,
                ),
            )
        log.info("DAO proposal created: %s type=%s community=%s", proposal_id, proposal_type, community_id)
        return p

    def cast_vote(
        self,
        proposal_id: str,
        voter_id: str,
        choice: int,
        db_path: str = _DB_PATH,
    ) -> Vote:
        prop = self._get_proposal(proposal_id, db_path)
        if prop is None:
            raise ValueError(f"Proposal '{proposal_id}' not found.")
        if prop.status != "active":
            raise ValueError(f"Proposal is not active (status={prop.status}).")
        if prop.is_expired():
            self._set_status(proposal_id, "expired", db_path)
            raise ValueError("Proposal has expired.")
        if choice < 0 or choice >= len(prop.options):
            raise ValueError(f"Invalid choice {choice}. Valid range: 0–{len(prop.options) - 1}.")

        weight = max(1.0, self._get_trust_weight(voter_id))
        vote_id = f"VOTE-{uuid.uuid4().hex[:12].upper()}"
        now = datetime.now(UTC).isoformat()
        vote = Vote(vote_id=vote_id, proposal_id=proposal_id, voter_id=voter_id,
                    choice=choice, weight=weight, created_at=now)

        try:
            with _db_lock, _conn(db_path) as con:
                con.execute(
                    """INSERT INTO dao_votes
                       (vote_id, proposal_id, voter_id, choice, weight, created_at)
                       VALUES (?,?,?,?,?,?)""",
                    (vote.vote_id, vote.proposal_id, vote.voter_id,
                     vote.choice, vote.weight, vote.created_at),
                )
        except sqlite3.IntegrityError as exc:
            raise ValueError(f"Voter '{voter_id}' has already voted on this proposal.") from exc

        log.info("Vote cast: %s proposal=%s voter=%s choice=%d weight=%.2f",
                 vote_id, proposal_id, voter_id, choice, weight)
        return vote

    def tally_votes(
        self,
        proposal_id: str,
        db_path: str = _DB_PATH,
    ) -> dict:
        """
        Tally weighted votes and determine pass/reject/pending.

        Returns:
          totals:        {option_index: total_weight}
          winner_index:  index of winning option (None if no votes)
          quorum_met:    bool
          status:        "passed" | "rejected" | "pending"
          total_voters:  int
          member_count:  int
        """
        prop = self._get_proposal(proposal_id, db_path)
        if prop is None:
            return {"status": "not_found"}

        with _conn(db_path) as con:
            rows = con.execute(
                "SELECT choice, weight FROM dao_votes WHERE proposal_id=?", (proposal_id,)
            ).fetchall()

        totals: dict[int, float] = dict.fromkeys(range(len(prop.options)), 0.0)
        for row in rows:
            idx = int(row["choice"])
            totals[idx] = totals.get(idx, 0.0) + float(row["weight"])

        member_count = self._count_members(prop.community_id, db_path)
        total_voters = len(rows)
        quorum_needed = max(2, math.ceil(_QUORUM_PCT * member_count))
        quorum_met = total_voters >= quorum_needed

        total_weight = sum(totals.values())
        if total_weight == 0:
            return {
                "totals": totals, "winner_index": None, "quorum_met": quorum_met,
                "status": "pending", "total_voters": total_voters, "member_count": member_count,
            }

        winner_idx = max(totals, key=lambda k: totals[k])
        winner_weight = totals[winner_idx]
        majority = winner_weight > total_weight * 0.5

        if quorum_met:
            status = "passed" if (winner_idx == 0 and majority) else "rejected"
        else:
            status = "pending"

        return {
            "totals": totals,
            "winner_index": winner_idx,
            "quorum_met": quorum_met,
            "status": status,
            "total_voters": total_voters,
            "member_count": member_count,
        }

    def execute_proposal(
        self,
        proposal_id: str,
        db_path: str = _DB_PATH,
    ) -> dict:
        prop = self._get_proposal(proposal_id, db_path)
        if prop is None:
            raise ValueError(f"Proposal '{proposal_id}' not found.")
        if prop.status != "passed":
            raise ValueError(f"Cannot execute proposal with status '{prop.status}'. Must be 'passed'.")

        tally = self.tally_votes(proposal_id, db_path)
        winner_idx = tally.get("winner_index") or 0
        winner_option = prop.options[winner_idx] if winner_idx < len(prop.options) else prop.options[0]

        if prop.proposal_type == "dispute_resolution":
            result = self._exec_dispute_resolution(prop, winner_option, db_path)
        elif prop.proposal_type == "agent_block":
            result = self._exec_agent_block(prop, winner_option, db_path)
        else:
            result = self._exec_parameter_change(prop, winner_option)

        self._set_status(proposal_id, "executed", db_path)
        log.info("Proposal executed: %s type=%s winner=%s", proposal_id, prop.proposal_type, winner_option)
        return {"executed": True, "proposal_id": proposal_id, "action": winner_option, **result}

    def get_proposals(
        self,
        community_id: str,
        status_filter: str | None = None,
        db_path: str = _DB_PATH,
        limit: int = 50,
    ) -> list[Proposal]:
        if status_filter:
            sql = (
                "SELECT * FROM dao_proposals WHERE community_id=? AND status=? "
                "ORDER BY created_at DESC LIMIT ?"
            )
            params: list = [community_id, status_filter, limit]
        else:
            sql = "SELECT * FROM dao_proposals WHERE community_id=? ORDER BY created_at DESC LIMIT ?"
            params = [community_id, limit]
        with _conn(db_path) as con:
            rows = con.execute(sql, params).fetchall()
        return [_row_to_proposal(r) for r in rows]

    def get_proposal(self, proposal_id: str, db_path: str = _DB_PATH) -> Proposal | None:
        return self._get_proposal(proposal_id, db_path)

    def get_votes(self, proposal_id: str, db_path: str = _DB_PATH) -> list[Vote]:
        with _conn(db_path) as con:
            rows = con.execute(
                "SELECT * FROM dao_votes WHERE proposal_id=? ORDER BY created_at DESC",
                (proposal_id,),
            ).fetchall()
        return [
            Vote(
                vote_id=r["vote_id"], proposal_id=r["proposal_id"], voter_id=r["voter_id"],
                choice=r["choice"], weight=r["weight"], created_at=r["created_at"],
            )
            for r in rows
        ]

    def check_active_proposal_for_escrow(
        self, escrow_id: str, db_path: str = _DB_PATH
    ) -> Proposal | None:
        """Return the active dispute_resolution proposal targeting this escrow, if any."""
        with _conn(db_path) as con:
            row = con.execute(
                """SELECT * FROM dao_proposals
                   WHERE target_id=? AND proposal_type='dispute_resolution' AND status='active'
                   ORDER BY created_at DESC LIMIT 1""",
                (escrow_id,),
            ).fetchone()
        return _row_to_proposal(row) if row else None

    def finalize_tally(self, proposal_id: str, db_path: str = _DB_PATH) -> dict:
        """
        Evaluate votes and persist pass/reject status if quorum is met.
        Call this after the proposal TTL to close voting.
        """
        tally = self.tally_votes(proposal_id, db_path)
        final = tally.get("status", "pending")
        if final in ("passed", "rejected"):
            self._set_status(proposal_id, final, db_path)
        return tally

    # ── Internals ─────────────────────────────────────────────────────────────

    def _get_proposal(self, proposal_id: str, db_path: str) -> Proposal | None:
        with _conn(db_path) as con:
            row = con.execute(
                "SELECT * FROM dao_proposals WHERE proposal_id=?", (proposal_id,)
            ).fetchone()
        return _row_to_proposal(row) if row else None

    def _set_status(self, proposal_id: str, status: str, db_path: str) -> None:
        with _db_lock, _conn(db_path) as con:
            con.execute(
                "UPDATE dao_proposals SET status=? WHERE proposal_id=?", (status, proposal_id)
            )

    def _count_members(self, community_id: str, db_path: str) -> int:
        try:
            with _conn(db_path) as con:
                row = con.execute(
                    "SELECT COUNT(*) AS cnt FROM marketplace_agents "
                    "WHERE community_id=? AND status='active'",
                    (community_id,),
                ).fetchone()
            return int(row["cnt"]) if row else 0
        except Exception:
            return 0

    def _get_trust_weight(self, voter_id: str) -> float:
        try:
            from warden.marketplace.trust_graph import TrustGraph  # noqa: PLC0415
            tg = TrustGraph()
            tg.build_graph()
            return max(1.0, tg.get_trust_score(voter_id) * 100.0)
        except Exception:
            return 1.0

    def _exec_dispute_resolution(self, prop: Proposal, winner_option: str, db_path: str) -> dict:
        release_to_buyer = winner_option == "release_to_buyer"
        try:
            from warden.marketplace.escrow import EscrowService  # noqa: PLC0415
            ok = EscrowService().resolve_dispute(
                prop.target_id, release_to_buyer, bypass_dao_check=True, db_path=db_path
            )
        except Exception as exc:
            return {"escrow_id": prop.target_id, "release_to_buyer": release_to_buyer,
                    "resolved": False, "error": str(exc)}
        return {"escrow_id": prop.target_id, "release_to_buyer": release_to_buyer, "resolved": ok}

    def _exec_agent_block(self, prop: Proposal, winner_option: str, db_path: str) -> dict:
        if winner_option != "block_agent":
            return {"agent_id": prop.target_id, "blocked": False, "reason": "community_voted_keep"}
        try:
            from warden.marketplace.agent import get_agent, update_capabilities  # noqa: PLC0415
            ag = get_agent(prop.target_id, db_path=db_path)
            tenant_id = ag.tenant_id if ag else "system"
            updated = update_capabilities(prop.target_id, tenant_id, [], db_path=db_path)
            return {"agent_id": prop.target_id, "blocked": updated, "capabilities_cleared": True}
        except Exception as exc:
            return {"agent_id": prop.target_id, "blocked": False, "error": str(exc)}

    def _exec_parameter_change(self, prop: Proposal, winner_option: str) -> dict:
        try:
            import redis as redis_lib  # noqa: PLC0415
            r = redis_lib.from_url(
                os.getenv("REDIS_URL", "redis://localhost:6379"), decode_responses=True
            )
            r.hset(f"marketplace:params:{prop.community_id}", prop.target_id, winner_option)
        except Exception as exc:
            log.warning("Redis unavailable for parameter_change: %s", exc)
        return {"param": prop.target_id, "value": winner_option, "community_id": prop.community_id}


is_dao_enabled = _DAO_ENABLED
