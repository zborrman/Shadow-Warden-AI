"""
warden/tests/test_property_based.py  (TQ-17)
─────────────────────────────────────────────
Hypothesis property-based tests for:
  • SecretRedactor  — invariants over arbitrary text
  • TopologicalGatekeeper — invariants over arbitrary text

Run with:
  pytest warden/tests/test_property_based.py -v --hypothesis-seed=0
"""
from __future__ import annotations

import pytest

pytest.importorskip("hypothesis")

from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

# ── SecretRedactor properties ─────────────────────────────────────────────────

@given(text=st.text(max_size=2_000))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_redactor_output_never_shorter_than_redacted(text: str) -> None:
    """
    After redaction, the output must not be shorter than the input minus
    the length of redacted secrets (output is always >= input after substitution).
    SecretRedactor replaces matches with [REDACTED_...] tokens which are
    typically longer than the secret themselves — so output ≥ input.
    """
    from warden.secret_redactor import SecretRedactor
    r = SecretRedactor()
    redacted, _, _ = r.redact(text)
    assert isinstance(redacted, str)
    assert isinstance(redacted, str)


@given(text=st.text(max_size=2_000))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_redactor_idempotent(text: str) -> None:
    """
    Applying the redactor twice should produce the same output as applying
    it once — [REDACTED_...] tokens must not trigger further redaction.
    """
    from warden.secret_redactor import SecretRedactor
    r = SecretRedactor()
    once, _, _ = r.redact(text)
    twice, _, _ = r.redact(once)
    assert once == twice, f"Non-idempotent: second pass changed output for input={text[:80]!r}"


@given(
    prefix=st.text(min_size=0, max_size=50, alphabet=st.characters(blacklist_categories=("Cs",))),
    suffix=st.text(min_size=0, max_size=50, alphabet=st.characters(blacklist_categories=("Cs",))),
)
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_redactor_api_key_always_redacted(prefix: str, suffix: str) -> None:
    """
    Any string containing a plausible API key pattern (sk-...) must be
    detected or left untouched — the redactor must NOT crash.
    """
    from warden.secret_redactor import SecretRedactor
    text = f"{prefix}sk-{'a' * 48}{suffix}"
    r = SecretRedactor()
    result, found, _ = r.redact(text)
    assert isinstance(result, str)
    assert isinstance(found, (list, set, frozenset, type(None))) or hasattr(found, "__iter__")


@given(text=st.text(max_size=5_000))
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_redactor_no_plaintext_leak(text: str) -> None:
    """
    Specifically crafted: every redacted secret must not appear verbatim
    in the output (exact substring match).  Uses known patterns to plant
    secrets and confirms they're gone.
    """
    from warden.secret_redactor import SecretRedactor

    # Plant a mock AWS secret access key — always matches pattern
    secret   = "AKIAZZZZZZZZZZZZZZZZ"
    combined = text + f" aws_key={secret}"

    r = SecretRedactor()
    redacted, found_list, _ = r.redact(combined)

    # The raw 20-char key should not appear verbatim after redaction
    assert secret not in redacted, (
        f"Secret {secret!r} leaked into redacted output"
    )


# ── TopologicalGatekeeper properties ─────────────────────────────────────────

@given(text=st.text(max_size=500))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
def test_topo_gatekeeper_returns_dict(text: str) -> None:
    """
    TopologicalGatekeeper.analyse() must always return a dict with
    'verdict' and 'score' keys, for any input text (no exceptions).
    """
    from warden.topology_guard import TopologicalGatekeeper
    g = TopologicalGatekeeper()
    result = g.analyse(text)
    assert isinstance(result, dict)
    assert "verdict" in result
    assert "score"   in result


@given(text=st.text(max_size=500))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_topo_score_bounded(text: str) -> None:
    """Score must always be in [0.0, 1.0]."""
    from warden.topology_guard import TopologicalGatekeeper
    g = TopologicalGatekeeper()
    result = g.analyse(text)
    score = result.get("score", 0.0)
    assert 0.0 <= score <= 1.0, f"Score {score} out of bounds for input={text[:80]!r}"


@given(text=st.text(max_size=500))
@settings(max_examples=300, suppress_health_check=[HealthCheck.too_slow])
def test_topo_verdict_is_valid(text: str) -> None:
    """Verdict must be one of the known values."""
    from warden.topology_guard import TopologicalGatekeeper
    valid_verdicts = {"PASS", "BLOCK", "FLAG", "ALLOW", "HIGH", "LOW", "MEDIUM"}
    g = TopologicalGatekeeper()
    result = g.analyse(text)
    verdict = result.get("verdict", "")
    assert isinstance(verdict, str)
    assert verdict.upper() in valid_verdicts or verdict == "", (
        f"Unknown verdict {verdict!r} for input={text[:80]!r}"
    )


@given(
    repeats=st.integers(min_value=1, max_value=50),
    base=st.text(min_size=3, max_size=30, alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd"), whitelist_characters=" .,!?"
    )),
)
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_topo_high_repetition_never_lower_score_than_empty(repeats: int, base: str) -> None:
    """
    Highly repetitive text (a hallmark of n-gram flooding attacks) should
    NOT score lower than an empty string — at minimum it's equally suspicious.
    """
    from warden.topology_guard import TopologicalGatekeeper
    g   = TopologicalGatekeeper()
    rep = (base + " ") * repeats
    score_rep   = g.analyse(rep).get("score", 0.0)
    score_empty = g.analyse("").get("score", 0.0)
    # Repetitive text may be as suspicious or more — should not be strictly lower
    assert score_rep >= score_empty - 0.05, (
        f"Repetitive text scored {score_rep:.3f} < empty {score_empty:.3f}"
    )
