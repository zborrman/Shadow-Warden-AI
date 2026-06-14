"""
warden/tests/test_governance.py
────────────────────────────────
Tests for Community DAO Governance (warden/marketplace/governance.py).

Environment isolation
─────────────────────
Each test class uses a unique temp SQLite file so tests never share state.
"""
from __future__ import annotations

import os
import tempfile
import uuid

import pytest

os.environ.setdefault("WARDEN_API_KEY", "")
os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
os.environ.setdefault("ANTHROPIC_API_KEY", "")


def _tmp_db() -> str:
    fd, path = tempfile.mkstemp(suffix=".db", prefix="test_gov_")
    os.close(fd)
    return path


def _cid() -> str:
    return f"community-{uuid.uuid4().hex[:8]}"


def _aid() -> str:
    return f"did:shadow:{uuid.uuid4().hex[:16]}"


# ── helpers ───────────────────────────────────────────────────────────────────

def _register_agents(db_path: str, community_id: str, n: int) -> list[str]:
    """Insert n fake active agents for quorum calculation."""
    import sqlite3
    ids = [_aid() for _ in range(n)]
    con = sqlite3.connect(db_path)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""
        CREATE TABLE IF NOT EXISTS marketplace_agents (
            agent_id TEXT PRIMARY KEY, community_id TEXT, tenant_id TEXT,
            capabilities TEXT DEFAULT '[]', status TEXT DEFAULT 'active',
            mandate_id TEXT DEFAULT '', created_at TEXT NOT NULL
        )
    """)
    for aid in ids:
        con.execute(
            "INSERT OR IGNORE INTO marketplace_agents (agent_id, community_id, tenant_id, created_at)"
            " VALUES (?,?,?,datetime('now'))",
            (aid, community_id, "t1"),
        )
    con.commit()
    con.close()
    return ids


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestCreateProposal:
    def test_create_dispute_resolution(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=_cid(), proposer_id=_aid(),
            proposal_type="dispute_resolution", target_id="ESC-ABCDEF",
            title="Dispute test", db_path=db,
        )
        assert p.proposal_id.startswith("PROP-")
        assert p.proposal_type == "dispute_resolution"
        assert p.status == "active"
        assert "release_to_buyer" in p.options
        assert "release_to_seller" in p.options

    def test_create_agent_block(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        p = GovernanceService().create_proposal(
            community_id=_cid(), proposer_id=_aid(),
            proposal_type="agent_block", target_id=_aid(),
            title="Block bad agent", db_path=db,
        )
        assert p.proposal_type == "agent_block"
        assert "block_agent" in p.options

    def test_create_parameter_change(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        p = GovernanceService().create_proposal(
            community_id=_cid(), proposer_id=_aid(),
            proposal_type="parameter_change", target_id="fee_pct",
            title="Change fee", db_path=db,
        )
        assert "approve" in p.options

    def test_unknown_type_raises(self):
        from warden.marketplace.governance import GovernanceService
        with pytest.raises(ValueError, match="Unknown proposal_type"):
            GovernanceService().create_proposal(
                community_id=_cid(), proposer_id=_aid(),
                proposal_type="invalid_type", target_id="x",
                title="Bad", db_path=_tmp_db(),
            )


class TestVoting:
    def test_cast_vote_returns_vote(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=_cid(), proposer_id=_aid(),
            proposal_type="dispute_resolution", target_id="ESC-X",
            title="Vote test", db_path=db,
        )
        vote = svc.cast_vote(proposal_id=p.proposal_id, voter_id=_aid(), choice=0, db_path=db)
        assert vote.vote_id.startswith("VOTE-")
        assert vote.choice == 0
        assert vote.weight >= 1.0

    def test_duplicate_vote_rejected(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        svc = GovernanceService()
        voter = _aid()
        p = svc.create_proposal(
            community_id=_cid(), proposer_id=_aid(),
            proposal_type="agent_block", target_id=_aid(),
            title="Dup vote test", db_path=db,
        )
        svc.cast_vote(p.proposal_id, voter, 0, db_path=db)
        with pytest.raises(ValueError, match="already voted"):
            svc.cast_vote(p.proposal_id, voter, 1, db_path=db)

    def test_invalid_choice_raises(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=_cid(), proposer_id=_aid(),
            proposal_type="dispute_resolution", target_id="E1",
            title="Choice test", db_path=db,
        )
        with pytest.raises(ValueError, match="Invalid choice"):
            svc.cast_vote(p.proposal_id, _aid(), choice=99, db_path=db)

    def test_vote_on_nonexistent_proposal_raises(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        with pytest.raises(ValueError, match="not found"):
            GovernanceService().cast_vote("PROP-NOTREAL", _aid(), 0, db_path=db)


class TestTally:
    def test_tally_shows_correct_totals(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        cid = _cid()
        _register_agents(db, cid, 20)
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=cid, proposer_id=_aid(),
            proposal_type="dispute_resolution", target_id="ESC-T1",
            title="Tally test", db_path=db,
        )
        for _ in range(4):
            svc.cast_vote(p.proposal_id, _aid(), choice=0, db_path=db)
        for _ in range(2):
            svc.cast_vote(p.proposal_id, _aid(), choice=1, db_path=db)

        tally = svc.tally_votes(p.proposal_id, db_path=db)
        assert tally["totals"][0] >= 4.0
        assert tally["totals"][1] >= 2.0
        assert tally["winner_index"] == 0
        assert tally["total_voters"] == 6

    def test_quorum_not_met_gives_pending(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        cid = _cid()
        _register_agents(db, cid, 100)   # 15% quorum = 15 voters needed
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=cid, proposer_id=_aid(),
            proposal_type="dispute_resolution", target_id="ESC-Q",
            title="Quorum test", db_path=db,
        )
        # Only 2 votes — below quorum of 15
        svc.cast_vote(p.proposal_id, _aid(), 0, db_path=db)
        svc.cast_vote(p.proposal_id, _aid(), 0, db_path=db)
        tally = svc.tally_votes(p.proposal_id, db_path=db)
        assert tally["quorum_met"] is False
        assert tally["status"] == "pending"

    def test_quorum_met_proposal_passes(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        cid = _cid()
        _register_agents(db, cid, 10)    # 15% quorum = max(2, ceil(1.5)) = 2
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=cid, proposer_id=_aid(),
            proposal_type="dispute_resolution", target_id="ESC-P",
            title="Pass test", db_path=db,
        )
        # 3 votes for option 0, 1 for option 1 — majority + quorum met
        for _ in range(3):
            svc.cast_vote(p.proposal_id, _aid(), 0, db_path=db)
        svc.cast_vote(p.proposal_id, _aid(), 1, db_path=db)

        tally = svc.tally_votes(p.proposal_id, db_path=db)
        assert tally["quorum_met"] is True
        assert tally["status"] == "passed"

    def test_rejected_when_minority_wins(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        cid = _cid()
        _register_agents(db, cid, 10)
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=cid, proposer_id=_aid(),
            proposal_type="agent_block", target_id=_aid(),
            title="Reject test", db_path=db,
        )
        # option 0: 1 vote, option 1: 3 votes → winner_index=1, not 0 → rejected
        svc.cast_vote(p.proposal_id, _aid(), 0, db_path=db)
        for _ in range(3):
            svc.cast_vote(p.proposal_id, _aid(), 1, db_path=db)

        tally = svc.tally_votes(p.proposal_id, db_path=db)
        assert tally["quorum_met"] is True
        assert tally["status"] == "rejected"


class TestExecute:
    def _pass_proposal(self, svc, p, db, n=4):
        for _ in range(n):
            svc.cast_vote(p.proposal_id, _aid(), 0, db_path=db)

    def test_execute_requires_passed_status(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        cid = _cid()
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=cid, proposer_id=_aid(),
            proposal_type="parameter_change", target_id="fee_pct",
            title="Not passed", db_path=db,
        )
        with pytest.raises(ValueError, match="status"):
            svc.execute_proposal(p.proposal_id, db_path=db)

    def test_execute_parameter_change(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        cid = _cid()
        _register_agents(db, cid, 10)
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=cid, proposer_id=_aid(),
            proposal_type="parameter_change", target_id="fee_pct",
            title="Fee change", db_path=db,
        )
        self._pass_proposal(svc, p, db)
        svc.finalize_tally(p.proposal_id, db_path=db)

        result = svc.execute_proposal(p.proposal_id, db_path=db)
        assert result["executed"] is True
        assert result["action"] == "approve"

        # Verify status is now "executed"
        updated = svc.get_proposal(p.proposal_id, db_path=db)
        assert updated is not None
        assert updated.status == "executed"

    def test_execute_agent_block_vote_keep(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        cid = _cid()
        _register_agents(db, cid, 10)
        svc = GovernanceService()
        target_agent = _aid()
        p = svc.create_proposal(
            community_id=cid, proposer_id=_aid(),
            proposal_type="agent_block", target_id=target_agent,
            title="Block agent", db_path=db,
        )
        # Vote for option 1 = "keep_agent" (reject block)
        for _ in range(4):
            svc.cast_vote(p.proposal_id, _aid(), 1, db_path=db)
        # Status will be "rejected" (winner_idx != 0), cannot execute
        svc.finalize_tally(p.proposal_id, db_path=db)
        prop = svc.get_proposal(p.proposal_id, db_path=db)
        assert prop is not None
        assert prop.status == "rejected"


class TestEscrowIntegration:
    def test_check_active_proposal_for_escrow(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        escrow_id = f"ESC-{uuid.uuid4().hex[:8].upper()}"
        cid = _cid()
        svc = GovernanceService()
        p = svc.create_proposal(
            community_id=cid, proposer_id=_aid(),
            proposal_type="dispute_resolution", target_id=escrow_id,
            title="Dispute resolution", db_path=db,
        )
        found = svc.check_active_proposal_for_escrow(escrow_id, db_path=db)
        assert found is not None
        assert found.proposal_id == p.proposal_id

    def test_no_active_proposal_returns_none(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        found = GovernanceService().check_active_proposal_for_escrow("ESC-NONE", db_path=db)
        assert found is None

    def test_get_proposals_by_status(self):
        from warden.marketplace.governance import GovernanceService
        db = _tmp_db()
        cid = _cid()
        svc = GovernanceService()
        for _ in range(3):
            svc.create_proposal(
                community_id=cid, proposer_id=_aid(),
                proposal_type="parameter_change", target_id="p",
                title="Active proposal", db_path=db,
            )

        active = svc.get_proposals(cid, status_filter="active", db_path=db)
        assert len(active) == 3

        passed = svc.get_proposals(cid, status_filter="passed", db_path=db)
        assert len(passed) == 0
