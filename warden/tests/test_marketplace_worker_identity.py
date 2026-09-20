"""
warden/tests/test_marketplace_worker_identity.py

`workers/shadow-warden-marketplace/` used to be a second implementation of the
marketplace — agents, listings, negotiations and clearing over Cloudflare KV, in
TypeScript, sharing no code, no database and no guard with `warden/marketplace/*`.

This file was written for that world. Its first half executed the Worker's own
`did.ts` under node and compared it against `pubkey_to_agent_id()`, because two
implementations of an identity function that disagree are worse than one; its
second half was a set of source ratchets over defects that existed only in the
Worker (#506): a DID takeover, a body-chosen identifier, an empty-secret admin
gate.

**The Worker is now a proxy** and owns none of that. The duplication is gone, so
the equivalence test has no second implementation to compare against and the
ratchets have no handler to guard. Keeping them would be keeping a guard over
code that no longer exists — the defect this repository names most often.

What replaces them is narrower and matches what is actually true: the Worker
must stay a proxy. Every defect #506 fixed was a consequence of it holding
state and deciding things; these tests fail if it starts doing either again.

Duplication removed rather than guarded twice is the point. `Rule.md` §29.2 and
`Hook.md` H-8 carry the history.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_REPO   = Path(__file__).resolve().parents[2]
_WORKER = _REPO / "workers" / "shadow-warden-marketplace"
_INDEX  = _WORKER / "src" / "index.ts"
_WRANGLER = _WORKER / "wrangler.toml"


def _code_only(ts: str) -> str:
    """The source with comments stripped.

    A source ratchet reads comments too, and that has now bitten twice: a
    comment explaining *why* `body.pubkey.slice(0, 512)` was wrong tripped the
    guard against it, and the header of this very file tripped the guards
    below by naming the handlers it describes removing. Prose about a defect is
    not the defect. Guards assert on code.
    """
    out, i, n = [], 0, len(ts)
    in_line = in_block = in_str = False
    quote = ""
    while i < n:
        c, nxt = ts[i], ts[i + 1] if i + 1 < n else ""
        if in_line:
            if c == "\n":
                in_line = False
                out.append(c)
        elif in_block:
            if c == "*" and nxt == "/":
                in_block = False
                i += 1
        elif in_str:
            out.append(c)
            if c == "\\":
                if i + 1 < n:
                    out.append(nxt)
                i += 1
            elif c == quote:
                in_str = False
        elif c == "/" and nxt == "/":
            in_line = True
            i += 1
        elif c == "/" and nxt == "*":
            in_block = True
            i += 1
        elif c in "\"'`":
            in_str, quote = True, c
            out.append(c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


@pytest.fixture(scope="module")
def src() -> str:
    """Code only — see `_code_only`."""
    return _code_only(_INDEX.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def raw() -> str:
    return _INDEX.read_text(encoding="utf-8")


def test_the_comment_stripper_keeps_code_and_drops_prose():
    """Guards the guard: if this breaks, every ratchet below silently weakens."""
    sample = 'const a = 1; // registerAgent\n/* requireAdmin */ const b = "//not a comment";'
    code = _code_only(sample)
    assert "registerAgent" not in code
    assert "requireAdmin" not in code
    assert "const a = 1;" in code
    assert '"//not a comment"' in code, "a string is not a comment"


@pytest.fixture(scope="module")
def wrangler() -> str:
    return _WRANGLER.read_text(encoding="utf-8")


# ── it forwards, and owns nothing ────────────────────────────────────────────


def test_the_worker_holds_no_state(wrangler: str, src: str):
    """No KV binding, and nothing reading one.

    State is what made it a second marketplace: a listing store it served, an
    agent registry it could be made to overwrite, and counters nobody
    reconciled against the gateway.
    """
    assert "kv_namespaces" not in wrangler, (
        "A KV binding is how this Worker became a second marketplace. "
        "The gateway owns marketplace state."
    )
    assert "MARKETPLACE_KV" not in src
    assert ".put(" not in src and ".get(" not in src.replace("headers.get(", "").replace(
        "searchParams.get(", ""
    ), "the proxy must not read or write a store"


def test_it_forwards_to_the_gateway_under_the_versioned_prefix(src: str):
    """`/v1` is canonical. It is not a declared route — `APIVersionMiddleware`
    resolves it — so reading `main.py` suggests only `/marketplace` exists and
    makes `/v1` look like a 404. It is not: production answers 200 on both, and
    the unversioned surface carries `Sunset: 2027-08-23`."""
    assert '"/v1/marketplace"' in src
    assert "WARDEN_BACKEND_URL" in src


def test_the_backend_url_is_configured_not_remembered(wrangler: str):
    """It shipped documented as a secret. It is a public hostname, and treating
    it as a credential put a manual step in front of a deploy — the kind that
    gets skipped, leaving a proxy answering 503 for everything. Declared in
    `[vars]`, the config is self-sufficient."""
    assert 'WARDEN_BACKEND_URL = "https://api.shadow-warden-ai.com"' in wrangler
    assert "wrangler secret put" not in wrangler, (
        "No secret is required by this Worker any more."
    )


def test_no_backend_configured_fails_closed(src: str):
    """An unreachable origin must produce an error, not an answer.

    Serving anything from the edge while the gateway is unavailable is exactly
    how a demo listing stayed public for months: a reply that looks like the
    market beats an error that admits it is unavailable, right up until someone
    believes it.
    """
    assert "backend_not_configured" in src
    assert "503" in src
    assert "backend_unreachable" in src


def test_it_does_not_invent_discovery_documents(src: str):
    """It published its own `/.well-known/agent.json` with a capability list
    that differed from the gateway's. Two discovery documents that must agree,
    and did not. Now the path is forwarded, not answered."""
    assert "PASSTHROUGH" in src
    assert '"/.well-known/agent.json"' in src
    assert '"@context"' not in src, "the Worker must not author an agent card"


def test_the_real_client_reaches_the_gateway(src: str):
    """`get_client_ip` keys ERS, shadow ban and rate limiting. If the proxy
    drops the client, every anonymous caller lands in one bucket and a single
    attacker shadow-bans the internet."""
    assert "CF-Connecting-IP" in src
    assert "X-Forwarded-For" in src


def test_the_edge_does_not_report_on_the_gateways_health(src: str):
    """A proxy answering `/health` says only that the proxy is up. Claiming the
    upstream is healthy without asking is a measurement nobody took."""
    assert 'role: "proxy"' in src, (
        "Assert the exact field the Worker emits — the object literal, not the "
        'JSON spelling. A disjunct with a bare "proxy" token would pass on a '
        "CORS string or an error message, which is a ratchet that cannot fail."
    )


# ── the duplication must not come back ───────────────────────────────────────


@pytest.mark.parametrize(
    "gone,why",
    [
        ("registerAgent", "agent registration belongs to the gateway (#463, #506)"),
        ("requireAdmin", "the admin gate was the empty-secret anti-pattern"),
        ("didMatchesPubkey", "identity derivation lived in two languages"),
        ("computeFee", "the take rate was computed twice, in float"),
        ("clearNegotiation", "clearing is a money path with one home"),
        ("SPONSORED_BOOST", "sponsorship decided listing order in a second store"),
    ],
)
def test_marketplace_logic_did_not_return_to_the_edge(src: str, gone: str, why: str):
    assert gone not in src, f"{gone} is back in the Worker — {why}"


def test_the_removed_derivation_module_stays_removed():
    assert not (_WORKER / "src" / "did.ts").exists(), (
        "did.ts reimplemented pubkey_to_agent_id in TypeScript. A proxy has no "
        "reason to derive a DID, and two implementations of an identity "
        "function is what this refactor removed."
    )
