"""
warden/tests/test_marketplace_worker_identity.py

The marketplace has two implementations. `warden/marketplace/*` is the FastAPI
gateway on api.shadow-warden-ai.com; `workers/shadow-warden-marketplace/` is a
TypeScript Worker over Cloudflare KV, deployed at marketplace.shadow-warden-ai.com.
They share no code, no database and no guard — and every other marketplace
ratchet in this suite enumerates FastAPI routes, so until this file none of them
had ever looked at the Worker.

What shipped there, found on PR #504:

  * `registerAgent()` re-registered an existing DID by overwriting `pubkey`
    while preserving `trust_score`, unauthenticated, answering 200 — the
    takeover closed on the Python side in #463, with the victim's reputation
    inherited rather than reset.
  * `did` came from the request body and was never derived from `pubkey`, so a
    caller could claim any identifier, including one already in use on the
    gateway.
  * `requireAdmin()` was `if (!env.ADMIN_KEY) return null; // → open`.

Two kinds of test here, because one kind is not enough:

  1. **Cross-implementation equivalence.** `did.ts` is executed under node and
     compared against `pubkey_to_agent_id()` over shared vectors. Two
     independent implementations of an identity function that disagree are
     worse than one: the same key would name two different agents, and a
     signature verified on one surface would not verify on the other. A
     source-grep can never catch that.
  2. **Source ratchets** over `index.ts`, for the properties that are only
     observable inside workerd (a KV write, an HTTP status). They assert the
     *absence* of the three anti-patterns, so a future edit that restores one
     fails here. They are deliberately narrow: each names the exact string that
     was the defect.

**What this file does NOT cover, so nobody reads it as more than it is.** The
Worker still has no actor proof anywhere else: `sendOffer`, `acceptOffer`,
`rejectOffer` and `POST /clear` all act on a body-supplied DID with no
signature, and `POST /clear` is reachable by anyone — it computes a take rate
but settles nothing, so it is a state-mutation gap rather than a money one. That
is the job `_assert_actor()` does on the FastAPI side (MP-1b), and porting it
here is its own piece of work. Fixing registration does not fix negotiation.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
from pathlib import Path

import pytest

from warden.marketplace.agent import pubkey_to_agent_id

_REPO = Path(__file__).resolve().parents[2]
_WORKER = _REPO / "workers" / "shadow-warden-marketplace" / "src"
_INDEX_TS = _WORKER / "index.ts"
_DID_TS = _WORKER / "did.ts"


# ── Vectors ───────────────────────────────────────────────────────────────────
# Fixed base64 Ed25519-sized (32-byte) public keys. Fixed rather than generated:
# a vector that changes per run cannot pin a cross-language result.
_PUBKEYS = [
    "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    "/////////////////////////////////////////w==",
    "3q2+7w==",
    "SGVsbG8sIFNoYWRvdyBXYXJkZW4gTTJNIG1hcmtldA==",
]


def _node() -> str:
    exe = shutil.which("node")
    if not exe:  # pragma: no cover - environment-dependent
        pytest.skip("node is not on PATH; cannot execute did.ts")
    return exe


def _run_worker_did(pubkeys: list[str]) -> list[str]:
    """Execute the Worker's own derivation under node and return its answers.

    `did.ts` is plain TypeScript with no Worker bindings, and the only
    TypeScript in it is the type annotations — stripping them with a regex would
    be its own source of error, so node's built-in type stripping does the work
    (`--experimental-strip-types`, on by default from node 22.18).
    """
    # A file:// URL, not a path: node's ESM loader rejects a bare "c:\\..." with
    # ERR_UNSUPPORTED_ESM_URL_SCHEME, so this must not be a plain str(path).
    script = textwrap.dedent(
        f"""
        import {{ pubkeyToDid }} from {json.dumps(_DID_TS.as_uri())};
        const keys = {json.dumps(pubkeys)};
        const out = [];
        for (const k of keys) out.push(await pubkeyToDid(k));
        process.stdout.write(JSON.stringify(out));
        """
    ).strip()

    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [_node(), "--experimental-strip-types", "--input-type=module", "--eval", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:  # pragma: no cover - surfaces a real breakage
        pytest.fail(f"node failed running did.ts:\n{proc.stderr}")
    return json.loads(proc.stdout)


# ── 1. Cross-implementation equivalence ───────────────────────────────────────


def test_worker_derives_the_same_did_as_the_gateway():
    """One key must name one agent, whichever surface answers."""
    expected = [pubkey_to_agent_id(k) for k in _PUBKEYS]
    assert _run_worker_did(_PUBKEYS) == expected


def test_the_derivation_is_not_trivially_constant():
    """Guards the test itself: two keys must not collapse to one DID."""
    got = _run_worker_did(_PUBKEYS)
    assert len(set(got)) == len(_PUBKEYS)
    assert all(d.startswith("did:shadow:") and len(d) == len("did:shadow:") + 32 for d in got)


# ── 2. Source ratchets over index.ts ──────────────────────────────────────────


@pytest.fixture(scope="module")
def index_src() -> str:
    return _INDEX_TS.read_text(encoding="utf-8")


def test_register_refuses_an_existing_did_instead_of_overwriting(index_src: str):
    """Rule 29 on the Worker: first registration wins, and it answers 409."""
    assert "agent already registered" in index_src, (
        "registerAgent() must refuse an existing DID. Re-registration is not an "
        "update path — nothing here can prove the caller is the incumbent."
    )
    assert "409" in index_src


def test_register_does_not_carry_state_over_from_an_existing_record(index_src: str):
    """The takeover was the carry-over: a new key inheriting the victim's trust."""
    for carried in ("existing?.trust_score", "existing?.registered_at", "existing?.is_sponsored"):
        assert carried not in index_src, (
            f"`{carried}` reintroduces the takeover: it lets a re-registration keep "
            "the incumbent's standing while replacing its key."
        )
    assert "existing ? 200 : 201" not in index_src, (
        "Answering 200 for an existing DID is the signature of an overwrite."
    )


def test_register_requires_the_did_to_be_derived_from_the_pubkey(index_src: str):
    assert "didMatchesPubkey" in index_src, (
        "A body-supplied DID proves nothing. agent_id is derived from the key — "
        "that derivation is what makes a signature self-proving."
    )


def test_admin_gate_is_fail_closed(index_src: str):
    """§29.1's third anti-pattern: an empty secret must not disable the check."""
    assert "if (!env.ADMIN_KEY) return null" not in index_src, (
        "An unset ADMIN_KEY must deny, not open. A deployment that forgot the "
        "secret would otherwise be indistinguishable from one that set it."
    )
    assert "admin key not configured" in index_src


def test_admin_key_comparison_leaks_neither_content_nor_length(index_src: str):
    """A byte-wise loop must return early when lengths differ, which times out
    the secret's length. Hashing both sides first makes every comparison run
    over the same 32 bytes, so only equality is observable."""
    assert "secretEquals" in index_src
    assert 'key !== env.ADMIN_KEY' not in index_src
    assert "a.length !== b.length" not in index_src, (
        "An early length return is how the key's length leaks — hash both sides."
    )
    assert 'crypto.subtle.digest("SHA-256"' in index_src


def test_the_stored_pubkey_is_the_one_the_did_was_derived_from(index_src: str):
    """Deriving from the full key and storing a truncation produces a record
    whose stored key does not derive its own DID — the invariant this handler
    exists to establish, broken by a `.slice()`."""
    assert "body.pubkey.slice(0, 512)" not in index_src, (
        "Truncating after validation decouples the stored key from the DID. "
        "Bound the length first and reject, then store exactly what was validated."
    )
    assert "MAX_PUBKEY_CHARS" in index_src
    assert "pubkey too long" in index_src
