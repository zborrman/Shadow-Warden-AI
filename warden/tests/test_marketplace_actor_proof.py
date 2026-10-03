"""
warden/tests/test_marketplace_actor_proof.py — the H-2 guard.

`warden/marketplace/CLAUDE.md` rule #25: **an API key authenticates a tenant,
not an agent.** `require_api_key` proves *who is calling*; it says nothing about
*which agent an action is attributed to*. A route that accepts
`from_agent_id` / `seller_agent_id` / `buyer_agent_id` / `caller_did` as body
text and then acts on it lets any authenticated caller act as anybody — which is
how a $1000 listing was once settled at $0.01 by impersonating the seller on
accept (`audit_m2m_marketplace_structure`).

`test_marketplace_route_auth.py` checks the first half, that a write route
carries an authentication dependency at all. **Nothing checked the second half**
(gap H-2), and four defects of exactly this shape — claimed identity used in
place of proven identity — were found by hand in a single session.

Only two routes prove it today. `_assert_actor()` verifies an Ed25519 signature
over `build_offer_canonical(...)` against the agent's registered public key;
because `agent_id` is *derived from* that key
(`did:shadow:{base62(sha256(pubkey))}`), a valid signature **is** proof of the
claimed identity. The other thirteen act on the claim.

So this is a may-only-shrink baseline, not a ban: thirteen routes predate the
rule and each needs its own signed envelope before it can be removed from
`_UNPROVEN`. What the guard buys is that a **fourteenth cannot be added
silently** — a new route taking an agent id in its body fails until somebody
classifies it.

Two things it deliberately does not claim:

* It does not say the thirteen are exploitable by an anonymous caller. They are
  behind `require_api_key`; the exposure is between tenants, not to the world.
* It does not verify enforcement for the two that pass, and the wiring is
  thinner than "proven" suggests. `_assert_actor` always checks that the agent
  is a *party* to the negotiation, but when no signature is supplied and
  `MARKETPLACE_REQUIRE_SIGNED_OFFERS` is off it returns without verifying
  anything at all. Those two routes therefore prove identity only when a
  signature is present and enforcement is on. Wiring and enforcement are
  different claims — Rule.md §29.1 — and this guard sees only the wiring.

Regenerate after a genuine reduction (an increase fails before it can write):

    UPDATE_ACTOR_PROOF_BASELINE=1 pytest warden/tests/test_marketplace_actor_proof.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from warden.tests.test_marketplace_route_auth import (
    _CANONICAL_ENV,
    _ESSENTIAL_ENV,
    _PREFIXES,
    _REPO_ROOT,
)

_BASELINE = Path(__file__).parent / "actor_proof_baseline.json"

# Body fields that name an agent rather than describing one.
_AGENT_FIELD = r"(agent_id|_did$|^did$)"

# Routes whose handler path reaches a proof of the claimed identity, with the
# mechanism named. A route may only move *into* this table.
_PROVEN = {
    "POST /marketplace/negotiations/{negotiation_id}/offer":
        "NegotiationEngine.send_offer -> _assert_actor: Ed25519 over "
        "build_offer_canonical, verified against the agent's registered key",
    "POST /marketplace/negotiations/{negotiation_id}/accept":
        "NegotiationEngine.accept_offer -> _assert_actor, same envelope",
}

# The fields `_PROVEN` actually covers. Exempting a route wholesale would let it
# gain a *second* agent identifier — a new `*_did`, say — that the signature
# envelope says nothing about, and the exemption would carry the new claim too.
_PROVEN_FIELDS = {
    "POST /marketplace/negotiations/{negotiation_id}/offer": {"from_agent_id"},
    "POST /marketplace/negotiations/{negotiation_id}/accept": {"from_agent_id"},
}

# Why each unproven route is still here. A route in the baseline without a note
# fails the test: an unexplained exemption is how a real hole hides among
# accepted ones.
_UNPROVEN_REASONS = {
    "POST /marketplace/listings":
        "publishes a listing as seller_agent_id; only a Sybil check on the claim",
    "POST /marketplace/listings/{listing_id}/purchase":
        "buys as buyer_agent_id — money moves on a claimed identity",
    "POST /marketplace/escrow":
        "escrow created over claimed buyer and seller",
    "POST /marketplace/clear":
        "clearing on a claimed buyer; this is the shape of the $0.01 settlement",
    "POST /marketplace/negotiations":
        "opens a negotiation between two claimed parties",
    "POST /marketplace/assets":
        "registers an asset as seller_agent_id",
    "POST /marketplace/analytics/query":
        "caller_agent_id scopes the query. The Confused Deputy check validates "
        "the statement against that id, but the id itself is claimed, so a "
        "tenant can read another agent's rows by naming it",
    "POST /m2m-store/offers":
        "offer generated for a claimed agent_id",
    "POST /acp/cart":
        "_effective_tenant binds the tenant, never the agent",
    "POST /acp/cart/{cart_id}/checkout":
        "same: tenant bound, agent claimed, and this one spends",
    "POST /acp/refund":
        "same; PENDING_REVIEW softens it but the claim still names the agent",
    "POST /acp/token":
        "issues a Shared Payment Token to a claimed agent_id",
    "POST /a2a/tasks":
        "caller_did recorded as the task's caller with no proof",
}

_CHILD = r'''
import json, logging, re, sys
logging.basicConfig(level=logging.WARNING, stream=sys.stderr)
import warden.main as m

PREFIXES = tuple(json.loads(sys.argv[2]))
AGENT = re.compile(sys.argv[3], re.I)
WRITE = {"POST", "PUT", "PATCH", "DELETE"}
rows = {}

def agent_fields(route):
    """Agent-naming fields of the request body, read from the resolved schema.

    Taken from FastAPI's own dependant rather than from the source, so a renamed
    model or a field added elsewhere cannot drift away from what is measured.
    """
    out = set()
    dep = getattr(route, "dependant", None)
    for p in getattr(dep, "body_params", []) or []:
        ann = getattr(p, "type_", None) or getattr(
            getattr(p, "field_info", None), "annotation", None)
        fields = getattr(ann, "model_fields", None)
        if fields:
            out |= {f for f in fields if AGENT.search(f)}
        else:
            # `agent_id: str = Body(...)` has no model to look inside. Skipping
            # it would let a new route carry an agent id past this guard without
            # ever being classified — the one direction that must never be
            # silent.
            name = getattr(p, "name", "") or ""
            if AGENT.search(name):
                out.add(name)
    return out

def record(route, prefix=""):
    if type(route).__name__ == "_IncludedRouter":
        ctx = getattr(route, "include_context", None)
        sub = getattr(ctx, "prefix", "") or ""
        orig = getattr(route, "original_router", None)
        if orig is not None:
            for child in orig.routes:
                record(child, prefix + sub)
        return
    endpoint = getattr(route, "endpoint", None)
    path = getattr(route, "path", None)
    if endpoint is None and getattr(route, "routes", None):
        for child in route.routes:
            record(child, prefix)
        return
    if not path:
        return
    full = prefix + path
    if not full.startswith(PREFIXES):
        return
    methods = {x for x in (getattr(route, "methods", None) or set())} & WRITE
    if not methods:
        return
    fields = agent_fields(route)
    if not fields:
        return
    for meth in sorted(methods):
        rows[meth + " " + full] = sorted(fields)

for route in m.app.routes:
    record(route)

with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(rows, fh)
'''


def _measure() -> dict[str, list[str]]:
    """{"<METHOD> <path>": [agent fields]} for every write route in the cluster."""
    fd, out_path = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    env = {k: os.environ[k] for k in _ESSENTIAL_ENV if k in os.environ}
    env.update(_CANONICAL_ENV)
    tmp = Path(tempfile.gettempdir())
    env["MODEL_CACHE_DIR"] = os.environ.get("MODEL_CACHE_DIR", str(tmp / "warden_ap_models"))
    for var in ("LOGS_PATH", "DYNAMIC_RULES_PATH"):
        env[var] = os.environ.get(var, str(tmp / f"warden_ap_{var.lower()}"))
    try:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD, out_path,
             json.dumps(list(_PREFIXES)), _AGENT_FIELD],
            capture_output=True, text=True, timeout=600,
            cwd=str(_REPO_ROOT), env=env,
        )
        if proc.returncode != 0:
            pytest.fail(f"actor-proof measurement subprocess failed:\n{proc.stderr[-3000:]}")
        return json.loads(Path(out_path).read_text(encoding="utf-8"))
    finally:
        with __import__("contextlib").suppress(OSError):
            os.unlink(out_path)


@pytest.fixture(scope="module")
def measured() -> dict[str, list[str]]:
    return _measure()


def test_measurement_is_not_vacuous(measured: dict[str, list[str]]) -> None:
    """Guard the guard: if the app mounts empty, everything below passes free."""
    assert len(measured) >= 10, (
        f"only {len(measured)} route(s) with an agent id in the body — the app "
        f"probably failed to mount its routers, which would make this guard "
        f"silently vacuous"
    )
    # The two known-proven routes must be among the measured, or the field
    # pattern has stopped matching what it was written for.
    for route in _PROVEN:
        assert route in measured, f"{route} vanished from the measurement"


def test_no_new_route_acts_on_an_unproven_agent_id(
    measured: dict[str, list[str]],
) -> None:
    baseline: dict[str, list[str]] = (
        json.loads(_BASELINE.read_text(encoding="utf-8")) if _BASELINE.is_file() else {}
    )
    # A proven route is exempt only for the fields its proof covers. Anything
    # beyond them is an unproven claim on a route that merely looks settled.
    beyond = sorted(
        f"{r}: +{sorted(set(f) - _PROVEN_FIELDS.get(r, set()))}"
        for r, f in measured.items()
        if r in _PROVEN and set(f) - _PROVEN_FIELDS.get(r, set())
    )
    assert not beyond, (
        "a proven route takes an agent identifier its proof does not cover:\n  "
        + "\n  ".join(beyond)
        + "\n\n`_assert_actor` signs `from_agent_id`; another identifier on the "
          "same route is a separate claim and needs its own envelope."
    )

    fresh = {r: f for r, f in measured.items() if r not in _PROVEN}

    if os.getenv("UPDATE_ACTOR_PROOF_BASELINE") == "1":
        # Regeneration may only record a reduction. Writing whatever is measured
        # would let a new unproven route be laundered into the baseline by the
        # very command meant to prove one left it.
        grew = sorted(
            r for r, f in fresh.items()
            if r not in baseline or set(f) - set(baseline.get(r, []))
        )
        assert not grew, (
            "refusing to rewrite the baseline: it would grow by\n  "
            + "\n  ".join(grew)
            + "\n\nClassify the route instead — regeneration records a reduction, "
              "never an addition."
        )
        _BASELINE.write_text(
            json.dumps(dict(sorted(fresh.items())), indent=2) + "\n", encoding="utf-8"
        )
        pytest.skip("baseline rewritten")

    # A baselined route that gains another agent-identifying field is a new
    # claim on the same path; comparing route names alone would not see it.
    widened = sorted(
        f"{r}: +{sorted(set(f) - set(baseline[r]))}"
        for r, f in fresh.items()
        if r in baseline and set(f) - set(baseline[r])
    )
    assert not widened, (
        "a baselined route now takes more agent identifiers than it did:\n  "
        + "\n  ".join(widened)
        + "\n\nRe-classify it, or prove the new field the way `_assert_actor` does."
    )

    added = sorted(set(fresh) - set(baseline))
    assert not added, (
        "these routes take an agent identifier in the request body and nothing "
        "proves the caller controls it:\n  "
        + "\n  ".join(f"{r}  fields={measured[r]}" for r in added)
        + "\n\nAn API key authenticates a tenant, not an agent "
          "(warden/marketplace/CLAUDE.md rule #25). Either verify a signature "
          "over the claimed id the way `_assert_actor` does, or derive the id "
          "from the authenticated caller instead of reading it from the body."
    )


def test_a_fixed_route_leaves_the_baseline(measured: dict[str, list[str]]) -> None:
    """A route that gained a proof must be removed, or it can silently regress."""
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8")) if _BASELINE.is_file() else {}
    stale = sorted(set(baseline) & set(_PROVEN))
    assert not stale, (
        "listed as both proven and unproven: " + ", ".join(stale)
        + "\nRemove them from the baseline — that is what makes this a ratchet."
    )
    gone = sorted(set(baseline) - set(measured))
    assert not gone, (
        "in the baseline but no longer a route taking an agent id: "
        + ", ".join(gone) + "\nDrop them from the baseline."
    )


def test_every_unproven_route_has_a_recorded_reason() -> None:
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8")) if _BASELINE.is_file() else {}
    missing = sorted(set(baseline) - set(_UNPROVEN_REASONS))
    assert not missing, (
        "baselined with no note in _UNPROVEN_REASONS: " + ", ".join(missing)
        + " — an unexplained exemption is how a real hole hides among accepted ones"
    )


def test_the_proven_routes_still_call_the_proof() -> None:
    """`_PROVEN` is an exemption, so it has to be checked, not asserted.

    The first version of this test only confirmed `_assert_actor` still existed.
    It would have stayed green if `send_offer` stopped calling it, and the guard
    would then exempt two routes on the strength of a comment — the shape of
    defect this repository keeps finding in its own rules. This reads the
    methods `_PROVEN` names and fails if the call is gone.
    """
    import ast

    tree = ast.parse(
        (_REPO_ROOT / "warden" / "marketplace" / "negotiation.py").read_text(
            encoding="utf-8"
        )
    )
    def _calls_directly(fn: ast.AST) -> bool:
        """True only for a call in this function's own body.

        `ast.walk` would also count `_assert_actor` inside a nested `def` that
        nobody invokes — a proof that never runs reading as a proof that does.
        """
        stack = list(ast.iter_child_nodes(fn))
        while stack:
            node = stack.pop()
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue  # a nested definition is not this function's work
            if isinstance(node, ast.Call) and (
                getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            ) == "_assert_actor":
                return True
            stack.extend(ast.iter_child_nodes(node))
        return False

    callers = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _calls_directly(node)
    }
    for method in ("send_offer", "accept_offer"):
        assert method in callers, (
            f"negotiation.{method} no longer calls _assert_actor, but _PROVEN "
            f"still exempts the route that reaches it"
        )
    for route, how in _PROVEN.items():
        assert "_assert_actor" in how, f"{route}: no mechanism named"
