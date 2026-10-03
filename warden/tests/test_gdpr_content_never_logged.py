"""
warden/tests/test_gdpr_content_never_logged.py — the H-7 guard.

``CLAUDE.md`` calls "Content is NEVER logged — only metadata (type, length,
timing)" a hard requirement and a protected invariant. Nothing enforced it:
``test_gdpr_endpoints.py`` and ``test_gdpr_idor.py`` cover the export/purge
routes and IDOR, and the ``check-gdpr-content-log`` guard the old Hook.md
described existed nowhere. The detection lives in
``warden/hooks/gdpr_content_log.py``; this module is the merge gate, because CI
runs pytest and not pre-commit.

A log line is the one place content cannot be taken back from — logs ship to
Loki, to MinIO and to a SIEM — and the sites that logged content were the ones
that fire when input looks suspicious, so the payload most worth not keeping was
the one most likely to be written down. Four such sites were live when this
guard was written and are fixed in the same change:

    marketplace/injection_guard.py  2 sites  60 chars of the agent's message
    openai_proxy.py                 1 site   a snippet of sanitised model output
    tool_guard.py                   1 site   120 chars of a blocked tool result

Why a may-only-shrink baseline and not a ban: six call sites remain, and each
logs a *third-party* body or platform-generated text rather than request
content — see ``_BASELINE_REASONS``. They are recorded rather than rewritten
because the alternative is a suppression comment, which rots silently next to
code nobody re-reads. The count is the gate; the reasons are reviewable here.

Regenerate after a genuine reduction (an increase fails before it can write):

    UPDATE_GDPR_CONTENT_LOG_BASELINE=1 pytest warden/tests/test_gdpr_content_never_logged.py
"""
from __future__ import annotations

import json
import os
from collections import Counter
from pathlib import Path

import pytest

from warden.hooks.gdpr_content_log import CONTENT_NAMES, scan_file, scan_source

_WARDEN = Path(__file__).resolve().parent.parent
_BASELINE = Path(__file__).parent / "gdpr_content_log_baseline.json"

# Why each remaining file is in the baseline. A file in the baseline without a
# reason here fails the test: an unexplained exemption is how a real leak hides
# among accepted ones.
_BASELINE_REASONS = {
    "warden/brain/nemotron_client.py":
        "resp.text of a 4xx from NVIDIA NIM - a third-party error body, not our "
        "request. Worth revisiting: a validation error can echo the input back.",
    "warden/main.py":
        "dyn_rule.snippet is the first 60 chars of the Evolution Engine's own "
        "regex pattern (see the field's comment at main.py:331), not user text.",
    "warden/rag_evolver.py":
        "the platform LLM's proposed-rule output when it fails to parse as JSON, "
        "at DEBUG. Generated rule text, not customer content.",
    "warden/syndicates/invites_router.py":
        "resp.text of a peer platform's non-200 to a handshake callback.",
    "warden/telegram_alert.py":
        "resp.text of a non-200 from the Telegram Bot API.",
}


def _scan_tree() -> list:
    findings = []
    for py in sorted(_WARDEN.rglob("*.py")):
        rel = py.relative_to(_WARDEN.parent).as_posix()
        # tests say the word 'content' constantly; hooks/ holds the scanner,
        # whose own CONTENT_NAMES table would match itself.
        if "/tests/" in rel or "/hooks/" in rel:
            continue
        findings.extend(scan_file(py, rel))
    return findings


def test_no_new_content_in_log_calls() -> None:
    findings = _scan_tree()
    per_file = dict(sorted(Counter(f.path for f in findings).items()))

    if os.getenv("UPDATE_GDPR_CONTENT_LOG_BASELINE") == "1":
        _BASELINE.write_text(
            json.dumps({"total": len(findings), "per_file": per_file}, indent=2) + "\n",
            encoding="utf-8",
        )
        pytest.skip("baseline rewritten")

    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))
    base_per_file: dict[str, int] = baseline["per_file"]

    regressions = [
        f"{path}: {count} (baseline {base_per_file.get(path, 0)})"
        for path, count in per_file.items()
        if count > base_per_file.get(path, 0)
    ]
    assert not regressions, (
        "content reaches a log call in:\n  " + "\n  ".join(regressions)
        + "\n\nGDPR: content is never logged - only metadata (type, length, "
          "timing). Log len(x), not x. Offending lines:\n  "
        + "\n  ".join(
            str(f) for f in findings if f.path in {r.split(':')[0] for r in regressions}
        )
    )
    assert len(findings) <= baseline["total"], (
        f"{len(findings)} content-in-log sites, baseline {baseline['total']}"
    )


def test_every_baselined_file_has_a_recorded_reason() -> None:
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))
    missing = sorted(set(baseline["per_file"]) - set(_BASELINE_REASONS))
    assert not missing, (
        "baselined with no reason in _BASELINE_REASONS: " + ", ".join(missing)
        + " - an unexplained exemption is how a real leak hides among accepted ones"
    )


def test_the_baseline_is_not_a_blank_cheque() -> None:
    """A baseline that outgrew its subject stops being a gate."""
    baseline = json.loads(_BASELINE.read_text(encoding="utf-8"))
    assert baseline["total"] <= 10, (
        "the content-in-log baseline has grown past the point of being a floor; "
        "fix sites instead of recording them"
    )


# ── The guard must be able to fire ────────────────────────────────────────────
# Every anti-pattern in Rule.md §29.1 is a control that is present and permits
# everyone. These assert the scanner catches a leak and spares a measurement.

@pytest.mark.parametrize("src", [
    'log.warning("blocked: %r", content)',
    'logger.info("payload=%s", payload)',
    'log.debug("text %s", text[:200])',
    'log.error("in", extra={"prompt": prompt})',
    'log.info(json.dumps({"event": "x", "content": content}))',
    'log.warning("got %s", payload.get("content"))',
    'log.warning("got %s", payload["content"])',
    'self.logger.warning("decoded=%r", decoded)',
    'log.info(f"prompt was {prompt}")',
])
def test_scanner_catches_a_leak(src: str) -> None:
    assert scan_source(src, "x.py"), f"not caught: {src}"


# Four bypasses the first version of the scanner had, each found by review on
# the PR that introduced it and each verified missed before it was closed. They
# are named individually because the tree happens to contain none of them — so
# the ratchet count cannot notice a regression here, only these can.
@pytest.mark.parametrize("src", [
    # `sorted(text)` logs every character, `min(text)` logs one. Neither is a
    # measurement, and both were in the metadata exemption.
    'log.warning("%s", sorted(text))',
    'log.warning("%s", min(text))',
    'log.warning("%s", max(content))',
    # The most idiomatic way to obtain a logger was also the way past the guard:
    # the receiver is a Call, which `_is_logger_call` did not consider.
    'logging.getLogger(__name__).warning("%s", content)',
    'getLogger(__name__).error("%s", payload)',
    # A serialising call is not a field selection: `body.label` logs a label,
    # `body.model_dump()` logs the whole request.
    'log.info("%s", payload.model_dump())',
    'log.info("%s", request.model_dump())',
    'log.info("%s", body.dict())',
    'log.info("%s", request.model_dump_json())',
])
def test_scanner_catches_a_closed_bypass(src: str) -> None:
    assert scan_source(src, "x.py"), f"bypass reopened: {src}"


@pytest.mark.parametrize("src", [
    # The serialising rule must not make ordinary request handling illegal.
    'log.info("path=%s", request.url.path)',
    'log.info("method=%s", request.method)',
    'log.info("h=%s", hash(text))',
])
def test_the_bypass_fixes_did_not_overreach(src: str) -> None:
    assert not scan_source(src, "x.py"), f"false positive: {src}"


@pytest.mark.parametrize("src", [
    # The permitted shape: a measurement of content.
    'log.warning("len=%d", len(text))',
    'log.info("content_type=%s", content_type)',
    'log.info("tokens=%d", prompt_tokens)',
    # An object dereferenced to a non-content field.
    'log.info("ttl=%d", body.ttl_hours)',
    'log.info("label=%s", body.label)',
    # A string literal is not a value.
    'log.info("content blocked")',
    'log.warning("failed to parse body")',
    # Not a logger.
    'result.text("x", content)',
    'response.info(content)',
])
def test_scanner_spares_a_measurement(src: str) -> None:
    assert not scan_source(src, "x.py"), f"false positive: {src}"


def test_the_fixed_sites_stay_fixed() -> None:
    """The four leaks this guard was written for, named individually.

    The ratchet count alone would accept a fix being reverted in one file while
    another file improved by one.
    """
    for rel in (
        "warden/marketplace/injection_guard.py",
        "warden/openai_proxy.py",
        "warden/tool_guard.py",
    ):
        path = _WARDEN.parent / rel
        assert not scan_file(path, rel), f"{rel} logs content again"


def test_content_names_covers_the_request_field() -> None:
    """``FilterRequest.content`` is the field the invariant is about."""
    from warden.schemas import FilterRequest
    assert "content" in FilterRequest.model_fields
    assert "content" in CONTENT_NAMES
