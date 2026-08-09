"""
warden/tests/test_journal_stage_scores.py

`xai/chain.py` reconstructs a nine-stage causal chain per record. It read 27
fields; the journal wrote 7. Measured live on 2026-08-08 over 338 records,
`topology`, `brain`, `causal` and `ers` reported SKIP on **every single one**,
`obfuscation`/`secrets`/`phish` reported PASS on all 338 including the 313 that
were blocked, and `primary_cause` could only ever resolve to `semantic_rules`
or `decision`.

`build_entry()` now records the stage scores the `/filter` handler already had
in scope. What is pinned here:

  * a record that carries a score no longer renders that stage as SKIP,
  * a record that does not carry one still does — a missing key means "no
    score", not "scored zero", and an unconditional 0.0 would be a different
    and false claim,
  * content never enters the record: `closest_example` and `xai_rationale`
    stay out by design, not by accident.
"""
from __future__ import annotations

import inspect

from warden.analytics import logger as lg
from warden.xai.chain import build_chain


def _entry(**extra) -> dict:
    base = {
        "ts": "2026-08-08T12:00:00+00:00",
        "request_id": "r1",
        "allowed": False,
        "risk_level": "block",
        "flags": ["prompt_injection"],
        "secrets_found": [],
        "payload_len": 42,
        "payload_tokens": 10,
        "attack_cost_usd": 0.0,
        "elapsed_ms": 12.0,
        "strict": False,
    }
    base.update(extra)
    return base


def _verdicts(entry: dict) -> dict[str, str]:
    return {n.stage_id: n.verdict for n in build_chain(entry).nodes}


def test_scored_stages_are_no_longer_skipped():
    scored = _entry(
        semantic_score=0.91,
        causal_p_high_risk=0.82,
        ers_score=0.44,
        phish_score=0.10,
        se_score=0.05,
    )
    v = _verdicts(scored)
    for stage in ("brain", "causal", "ers"):
        assert v[stage] != "SKIP", f"{stage} still SKIP with a score present: {v}"


def test_a_record_without_scores_still_reports_skip():
    """A missing key means no score — not a score of zero."""
    v = _verdicts(_entry())
    assert v["brain"] == "SKIP" and v["causal"] == "SKIP"


def test_build_entry_omits_scores_it_was_not_given():
    entry = lg.build_entry(
        request_id="r", allowed=True, risk_level="low", flags=[], secrets_found=[],
        payload_len=1, payload_tokens=1, attack_cost_usd=0.0, elapsed_ms=1.0, strict=False,
    )
    for k in ("semantic_score", "causal_p_high_risk", "phish_score", "se_score", "ers_score"):
        assert k not in entry, f"{k} written as a default — that claims the stage ran"


def test_build_entry_records_the_scores_it_is_given():
    entry = lg.build_entry(
        request_id="r", allowed=False, risk_level="block", flags=[], secrets_found=[],
        payload_len=1, payload_tokens=1, attack_cost_usd=0.0, elapsed_ms=1.0, strict=False,
        semantic_score=0.912345, causal_p_high_risk=0.5, ers_score=0.25,
        phish_score=0.1, se_score=0.2,
        obfuscation_layers=2, obfuscation_types=["base64", "rot13"],
    )
    assert entry["semantic_score"] == 0.9123          # rounded, not truncated
    assert entry["causal_p_high_risk"] == 0.5
    assert entry["obfuscation_layers"] == 2
    assert entry["obfuscation_types"] == ["base64", "rot13"]


def test_no_content_bearing_field_was_added():
    """The journal is metadata-only (docs/dpia.md). Scores yes, text never."""
    # Comments stripped: this function documents *why* those fields are
    # excluded, and a guard that trips on its own rationale gets deleted.
    src = "\n".join(
        ln for ln in inspect.getsource(lg.build_entry).splitlines()
        if not ln.lstrip().startswith("#")
    )
    for forbidden in ("closest_example", "xai_rationale", "decoded", "payload_text"):
        assert forbidden not in src, (
            f"build_entry gained `{forbidden}` — that is content, not a score"
        )


def test_the_filter_handler_passes_every_new_field():
    """A field added to the builder and never passed is a field that stays absent."""
    import warden.main as m

    src = inspect.getsource(m)
    # The handler collects these by name into `_stage_scores` and splats that
    # into build_entry(), so check the collection table rather than the call —
    # a field in the builder that never appears here is a field that is always
    # absent from the record, which is the failure this pins.
    table = src.split("_stage_scores: dict")[1].split("try:")[0]
    for field in ("semantic_score", "obfuscation_layers", "causal_p_high_risk",
                  "phish_score", "se_score", "ers_score"):
        assert field in table, f"/filter never collects {field}"
    assert "**_stage_scores" in src, "the collected scores are not passed to build_entry()"
