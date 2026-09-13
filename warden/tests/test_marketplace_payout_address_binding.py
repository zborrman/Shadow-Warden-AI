"""
warden/tests/test_marketplace_payout_address_binding.py — R1.

An agent is identified by an Ed25519 key; a trade settles to a secp256k1
Ethereum address. Nothing derives one from the other, so whoever can write
``payout_address`` decides where a seller is paid. Until R1 the only writer,
``set_payout_address()``, took no proof at all — and was wired to no route, so
no agent could ever be paid and every escrow snapshotted empty addresses.

These tests pin the binding: the agent signs ``{purpose, agent_id, address,
timestamp}`` with the key its DID is derived from, verified fail-CLOSED.
"""
from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import pytest

_ADDR_A = "0x52908400098527886E0F7030069857D2E4169EE7"
_ADDR_B = "0x8617E340B3D01FA5F11F306F4090FD50E238070D"


def _keypair():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    raw = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return priv, base64.b64encode(raw).decode()


def _now(offset_s: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=offset_s)).isoformat()


def _sign(priv, *, agent_id: str, address: str, timestamp: str) -> str:
    from warden.marketplace.agent import build_payout_address_canonical

    canonical = build_payout_address_canonical(
        agent_id=agent_id, address=address, timestamp=timestamp
    )
    return base64.b64encode(priv.sign(canonical)).decode()


@pytest.fixture
def agents(tmp_path, monkeypatch):
    """Two registered agents on an isolated DB."""
    db = str(tmp_path / "mkt.db")
    monkeypatch.setenv("MARKETPLACE_DB_PATH", db)

    from warden.marketplace import agent as agent_mod
    from warden.marketplace import listing as listing_mod

    agent_mod.reset_column_memo()
    listing_mod.reset_migration_memo()

    out = {}
    for name, tenant in (("seller", "t-seller"), ("other", "t-other")):
        priv, pub = _keypair()
        agent_mod.register_agent(
            tenant_id=tenant, community_id="C1", public_key_b64=pub,
            capabilities=["marketplace_sell"], db_path=db,
        )
        out[name] = (priv, agent_mod.pubkey_to_agent_id(pub))
    out["db"] = db
    yield out
    agent_mod.reset_column_memo()
    listing_mod.reset_migration_memo()


def _bind(agents, who, address, *, signer=None, timestamp=None, signature=None):
    from warden.marketplace.agent import bind_payout_address

    priv, agent_id = agents[who]
    ts = timestamp or _now()
    sig = signature
    if sig is None:
        signing_priv = agents[signer][0] if signer else priv
        sig = _sign(signing_priv, agent_id=agent_id, address=address, timestamp=ts)
    return bind_payout_address(
        agent_id, address, signature=sig, timestamp=ts, db_path=agents["db"]
    )


def _stored(agents, who):
    from warden.marketplace.agent import get_agent

    return get_agent(agents[who][1], db_path=agents["db"]).payout_address


# ── the happy path ──────────────────────────────────────────────────────────


def test_a_signed_binding_is_stored_checksummed(agents):
    stored = _bind(agents, "seller", _ADDR_A)
    assert stored == _ADDR_A
    assert _stored(agents, "seller") == _ADDR_A


def test_lowercase_input_must_be_signed_in_checksummed_form(agents):
    """The server normalises before verifying, so the client signs EIP-55."""
    from warden.marketplace.agent import PayoutAddressError, bind_payout_address

    priv, agent_id = agents["seller"]
    ts = _now()
    lower = _ADDR_A.lower()

    # Signed over the lowercase string: refused, the envelope does not match.
    bad = _sign(priv, agent_id=agent_id, address=lower, timestamp=ts)
    with pytest.raises(PayoutAddressError, match="does not verify"):
        bind_payout_address(agent_id, lower, signature=bad, timestamp=ts, db_path=agents["db"])

    # Signed over the checksummed form: accepted even though input was lowercase.
    good = _sign(priv, agent_id=agent_id, address=_ADDR_A, timestamp=ts)
    assert bind_payout_address(
        agent_id, lower, signature=good, timestamp=ts, db_path=agents["db"]
    ) == _ADDR_A


def test_clearing_the_address_also_requires_a_signature(agents):
    _bind(agents, "seller", _ADDR_A, timestamp=_now(-5))
    assert _bind(agents, "seller", "") == ""
    assert _stored(agents, "seller") == ""


# ── the theft primitive this closes ─────────────────────────────────────────


def test_another_agents_key_cannot_redirect_a_payout(agents):
    """The whole point: a signature must come from the agent it is attributed to."""
    from warden.marketplace.agent import PayoutAddressError

    with pytest.raises(PayoutAddressError, match="does not verify"):
        _bind(agents, "seller", _ADDR_B, signer="other")
    assert _stored(agents, "seller") == ""


def test_a_signature_cannot_be_moved_to_a_different_address(agents):
    from warden.marketplace.agent import PayoutAddressError

    priv, agent_id = agents["seller"]
    ts = _now()
    sig_for_a = _sign(priv, agent_id=agent_id, address=_ADDR_A, timestamp=ts)
    with pytest.raises(PayoutAddressError, match="does not verify"):
        _bind(agents, "seller", _ADDR_B, timestamp=ts, signature=sig_for_a)


def test_unsigned_is_refused_with_no_flag_to_disable_it(agents, monkeypatch):
    """Offers have a bake-in flag; this does not, and must not honour that one."""
    from warden.marketplace.agent import PayoutAddressError

    monkeypatch.setenv("MARKETPLACE_REQUIRE_SIGNED_OFFERS", "false")
    with pytest.raises(PayoutAddressError, match="must be signed"):
        _bind(agents, "seller", _ADDR_A, signature="")


def test_a_stale_timestamp_is_refused(agents):
    from warden.marketplace.agent import PayoutAddressError

    with pytest.raises(PayoutAddressError, match="acceptance window"):
        _bind(agents, "seller", _ADDR_A, timestamp=_now(-3600))


def test_a_captured_older_binding_cannot_roll_back_a_newer_one(agents):
    """Replay inside the skew window: sign A, then B; re-presenting A must fail."""
    from warden.marketplace.agent import PayoutAddressError

    priv, agent_id = agents["seller"]
    t_old, t_new = _now(-30), _now(-10)
    old_sig = _sign(priv, agent_id=agent_id, address=_ADDR_A, timestamp=t_old)

    _bind(agents, "seller", _ADDR_A, timestamp=t_old, signature=old_sig)
    _bind(agents, "seller", _ADDR_B, timestamp=t_new)
    assert _stored(agents, "seller") == _ADDR_B

    with pytest.raises(PayoutAddressError, match="roll back"):
        _bind(agents, "seller", _ADDR_A, timestamp=t_old, signature=old_sig)
    assert _stored(agents, "seller") == _ADDR_B


def test_an_offer_signature_cannot_be_presented_as_a_binding(agents):
    """Domain separation: the same Ed25519 key signs offers too."""
    from warden.marketplace.agent import PayoutAddressError
    from warden.marketplace.negotiation import build_offer_canonical

    priv, agent_id = agents["seller"]
    ts = _now()
    offer_bytes = build_offer_canonical(
        offer_type="offer", price=1.0, asset_ueciid=_ADDR_A, round_=1,
        agent_id=agent_id, timestamp=ts, negotiation_id="n",
    )
    offer_sig = base64.b64encode(priv.sign(offer_bytes)).decode()
    with pytest.raises(PayoutAddressError, match="does not verify"):
        _bind(agents, "seller", _ADDR_A, timestamp=ts, signature=offer_sig)


def test_unknown_agent_and_malformed_address_are_refused(agents):
    from warden.marketplace.agent import PayoutAddressError, bind_payout_address

    priv, _ = agents["seller"]
    ts = _now()
    ghost = "did:shadow:doesnotexist"
    sig = _sign(priv, agent_id=ghost, address=_ADDR_A, timestamp=ts)
    with pytest.raises(PayoutAddressError, match="not registered"):
        bind_payout_address(ghost, _ADDR_A, signature=sig, timestamp=ts, db_path=agents["db"])

    with pytest.raises(PayoutAddressError, match="not an Ethereum address"):
        _bind(agents, "seller", "0xnope")


# ── structural guards ───────────────────────────────────────────────────────


def test_no_unsigned_writer_of_payout_address_exists():
    """The unsigned setter is gone; nothing may bring back a write that skips proof.

    Any module other than agent.py that writes the column would be a second,
    unverified path to redirect a payout.
    """
    import re
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    writer = re.compile(r"SET\s+[^;\"']*\bpayout_address\s*=", re.I)
    offenders = []
    for path in root.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if writer.search(text) and path.name != "agent.py":
            offenders.append(str(path.relative_to(root)))
        if "def set_payout_address" in text:
            offenders.append(f"{path.relative_to(root)} (unsigned setter is back)")
    assert not offenders, f"unverified payout_address writers: {offenders}"


def test_route_rejects_an_unsigned_body(agents, monkeypatch):
    """End to end through the real router: 400, and nothing is written."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace.api_agents import router

    app = FastAPI()
    app.include_router(router, prefix="/marketplace")
    client = TestClient(app)

    _, agent_id = agents["seller"]
    r = client.put(
        f"/marketplace/agents/{agent_id}/payout-address",
        json={"address": _ADDR_A, "signature": "", "timestamp": _now()},
    )
    assert r.status_code == 400, r.text
    assert _stored(agents, "seller") == ""


def test_route_accepts_a_signed_body(agents):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace.api_agents import router

    app = FastAPI()
    app.include_router(router, prefix="/marketplace")
    client = TestClient(app)

    priv, agent_id = agents["seller"]
    ts = _now()
    r = client.put(
        f"/marketplace/agents/{agent_id}/payout-address",
        json={
            "address": _ADDR_A,
            "signature": _sign(priv, agent_id=agent_id, address=_ADDR_A, timestamp=ts),
            "timestamp": ts,
        },
    )
    assert r.status_code == 200, r.text
    assert r.json() == {"agent_id": agent_id, "payout_address": _ADDR_A}


# ── re-registration must never mutate an existing agent ─────────────────────
#
# Found by CodeRabbit on this PR, and pre-existing in production: registration
# is deliberately unauthenticated (Stage 1 first contact, owner decision D-5),
# `GET /agents/{id}` publishes the public key, and `register_agent` wrote with
# `INSERT OR REPLACE` and no existence check. SQLite's REPLACE deletes the row
# and inserts a fresh one, so anyone could re-submit a victim's public key and
# replace the victim's record wholesale. The attacker cannot sign as the victim,
# but the replacement alone was enough to: reassign the agent to another tenant,
# lift a suspension or deactivation, and wipe `payout_address_signed_at` — which
# silently disabled the rollback guard above.


def _reregister_as_attacker(agents, who):
    from warden.marketplace.agent import get_agent, register_agent

    victim = get_agent(agents[who][1], db_path=agents["db"])
    return register_agent(
        tenant_id="t-attacker", community_id="C-attacker",
        public_key_b64=victim.public_key,
        capabilities=["marketplace_buy", "marketplace_sell", "marketplace_negotiate"],
        db_path=agents["db"],
    )


def test_reregistering_a_public_key_cannot_take_over_the_agent(agents):
    from warden.marketplace.agent import get_agent

    _, agent_id = agents["seller"]
    with pytest.raises(ValueError, match="already registered"):
        _reregister_as_attacker(agents, "seller")

    after = get_agent(agent_id, db_path=agents["db"])
    assert after.tenant_id == "t-seller"
    assert after.community_id == "C1"
    assert after.capabilities == ["marketplace_sell"]


def test_reregistering_cannot_wipe_the_payout_binding_or_its_rollback_guard(agents):
    from warden.marketplace.agent import PayoutAddressError

    priv, agent_id = agents["seller"]
    t_old, t_new = _now(-30), _now(-10)
    old_sig = _sign(priv, agent_id=agent_id, address=_ADDR_A, timestamp=t_old)
    _bind(agents, "seller", _ADDR_A, timestamp=t_old, signature=old_sig)
    _bind(agents, "seller", _ADDR_B, timestamp=t_new)

    with pytest.raises(ValueError, match="already registered"):
        _reregister_as_attacker(agents, "seller")

    assert _stored(agents, "seller") == _ADDR_B
    # The guard still holds: the captured older binding is still refused.
    with pytest.raises(PayoutAddressError, match="roll back"):
        _bind(agents, "seller", _ADDR_A, timestamp=t_old, signature=old_sig)


def test_reregistering_cannot_lift_a_suspension(agents):
    from warden.marketplace.agent import get_agent, suspend_agent

    _, agent_id = agents["seller"]
    assert suspend_agent(agent_id, "t-seller", db_path=agents["db"])

    with pytest.raises(ValueError, match="already registered"):
        _reregister_as_attacker(agents, "seller")
    assert get_agent(agent_id, db_path=agents["db"]).status == "suspended"


def test_the_register_route_answers_409_for_an_existing_agent(agents):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from warden.marketplace.agent import get_agent
    from warden.marketplace.api_agents import router

    app = FastAPI()
    app.include_router(router, prefix="/marketplace")
    client = TestClient(app)

    victim = get_agent(agents["seller"][1], db_path=agents["db"])
    r = client.post(
        "/marketplace/agents/register",
        json={"tenant_id": "t-attacker", "community_id": "C-attacker",
              "public_key": victim.public_key, "capabilities": ["marketplace_sell"]},
    )
    assert r.status_code == 409, r.text
    assert get_agent(victim.agent_id, db_path=agents["db"]).tenant_id == "t-seller"


# ── concurrent binds must not interleave into a rollback ────────────────────


def test_the_ordering_check_and_the_write_are_one_statement(agents, monkeypatch):
    """Read-check-write let two concurrent binds both pass, older one landing last.

    Simulated deterministically: the newer binding lands between the older
    request's ordering check and its write. The older write must then refuse.
    """
    from warden.marketplace import agent as agent_mod
    from warden.marketplace.agent import PayoutAddressError

    priv, agent_id = agents["seller"]
    t_base, t_old, t_new = _now(-40), _now(-30), _now(-10)
    _bind(agents, "seller", _ADDR_A, timestamp=t_base)

    old_sig = _sign(priv, agent_id=agent_id, address=_ADDR_A, timestamp=t_old)
    real_verify = agent_mod._verify_payout_signature

    def verify_then_race(*args, **kwargs):
        ok = real_verify(*args, **kwargs)
        # The newer, legitimate binding commits while the older one is in flight.
        monkeypatch.setattr(agent_mod, "_verify_payout_signature", real_verify)
        _bind(agents, "seller", _ADDR_B, timestamp=t_new)
        return ok

    monkeypatch.setattr(agent_mod, "_verify_payout_signature", verify_then_race)
    with pytest.raises(PayoutAddressError, match="roll back"):
        _bind(agents, "seller", _ADDR_A, timestamp=t_old, signature=old_sig)
    assert _stored(agents, "seller") == _ADDR_B


def test_a_refused_registration_creates_no_mandate(agents, monkeypatch):
    """Only the registration whose INSERT wins may create an AP2 mandate.

    Check-then-create-then-insert let two concurrent registrations of one key
    both pass the check and both create a mandate, orphaning the loser's. The
    row is now reserved first, so a refused caller never reaches the mandate.
    Counted on the real processor, not a stub of register_agent.
    """
    from warden.business_community.agentic_commerce import ap2

    created = []
    real_create = ap2.AP2Processor.create_mandate

    def counting_create(self, *args, **kwargs):
        created.append(kwargs.get("tenant_id"))
        return real_create(self, *args, **kwargs)

    monkeypatch.setattr(ap2.AP2Processor, "create_mandate", counting_create)

    with pytest.raises(ValueError, match="already registered"):
        _reregister_as_attacker(agents, "seller")
    assert created == [], f"a refused registration created mandates for {created}"


def test_the_winning_registration_still_gets_its_mandate(tmp_path, monkeypatch):
    """Reordering must not cost the legitimate registrant its mandate."""
    from warden.business_community.agentic_commerce import ap2
    from warden.marketplace import agent as agent_mod

    db = str(tmp_path / "fresh.db")
    monkeypatch.setenv("MARKETPLACE_DB_PATH", db)
    agent_mod.reset_column_memo()

    class _M:
        id = "mandate-123"

    monkeypatch.setattr(ap2.AP2Processor, "create_mandate", lambda self, **kw: _M())
    _, pub = _keypair()
    returned = agent_mod.register_agent(
        tenant_id="t1", community_id="C1", public_key_b64=pub,
        capabilities=["marketplace_sell"], db_path=db,
    )
    stored = agent_mod.get_agent(returned.agent_id, db_path=db)
    assert returned.mandate_id == "mandate-123"
    assert stored.mandate_id == "mandate-123"
    agent_mod.reset_column_memo()


def test_an_unattached_mandate_is_revoked_and_not_reported(tmp_path, monkeypatch):
    """If attaching the mandate touches no row, it is revoked, and the response
    does not claim a mandate that is not stored."""
    from warden.business_community.agentic_commerce import ap2
    from warden.marketplace import agent as agent_mod

    db = str(tmp_path / "attach.db")
    monkeypatch.setenv("MARKETPLACE_DB_PATH", db)
    agent_mod.reset_column_memo()
    _, pub = _keypair()
    agent_id = agent_mod.pubkey_to_agent_id(pub)

    class _M:
        id = "mandate-orphan"

    def create_and_steal_the_slot(self, **kw):
        # Something else fills the reserved slot before our attach runs.
        with agent_mod._conn(db) as con:
            con.execute("UPDATE marketplace_agents SET mandate_id='other' WHERE agent_id=?",
                        (agent_id,))
            con.commit()
        return _M()

    revoked = []
    monkeypatch.setattr(ap2.AP2Processor, "create_mandate", create_and_steal_the_slot)
    monkeypatch.setattr(ap2.AP2Processor, "revoke_mandate",
                        lambda self, mid, tid: revoked.append((mid, tid)) or True)

    returned = agent_mod.register_agent(
        tenant_id="t1", community_id="C1", public_key_b64=pub,
        capabilities=["marketplace_sell"], db_path=db,
    )
    assert revoked == [("mandate-orphan", "t1")]
    assert returned.mandate_id == "", "response claimed a mandate that was never attached"
    assert agent_mod.get_agent(agent_id, db_path=db).mandate_id == "other"
    agent_mod.reset_column_memo()
