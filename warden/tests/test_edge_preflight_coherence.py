"""
warden/tests/test_edge_preflight_coherence.py

`cloudflare/preflight-worker/` sits on `api.shadow-warden-ai.com/*`, in front of
every route in this repository. Its limits are JavaScript constants in a
different directory from the Python settings they have to agree with, nothing
imports one from the other, and the Worker answers before any warden code runs
-- so a disagreement is a 413 the gateway never issued, on a request it never
saw, with no entry in any log warden writes.

There was one: a flat 1 MB body cap against a gateway that accepts
`DOC_INTEL_MAX_BYTES` (50 MB) of document, carried as base64 inside JSON on
`/filter`. Every document over ~768 KB would have been rejected at the edge
while the product advertised 50 MB. It never fired only because the Worker has
never been deployed.

These tests are what keeps the two numbers married.
"""
from __future__ import annotations

import math
import re
from pathlib import Path

import pytest

_WORKER = Path(__file__).resolve().parents[2] / "cloudflare" / "preflight-worker" / "src" / "index.js"

# base64 carries 3 bytes in every 4 characters, so a file of N bytes arrives as
# a body of at least 4N/3 before any JSON envelope.
_BASE64_INFLATION = 4 / 3


def _constant(name: str) -> int:
    """Read a numeric constant out of the Worker source.

    The values are written as readable arithmetic (`70 * 1024 * 1024`), so the
    expression is evaluated -- after being restricted to digits, underscores and
    the two operators that appear, which is what keeps this from executing the
    file.
    """
    src = _WORKER.read_text(encoding="utf-8")
    m = re.search(rf"^const {name} = ([^;]+);", src, re.MULTILINE)
    assert m, f"{name} is gone from {_WORKER.name} — the edge limit it named is now unpinned"
    expr = m.group(1).split("//")[0].strip().replace("_", "")
    assert re.fullmatch(r"[\d\s*+]+", expr), f"{name} is no longer a plain arithmetic literal: {expr!r}"
    return int(eval(expr))  # noqa: S307 — the pattern above admits only digits and * +


def _document_prefixes() -> list[str]:
    src = _WORKER.read_text(encoding="utf-8")
    m = re.search(r"const DOCUMENT_PREFIXES = \[(.*?)\];", src, re.DOTALL)
    assert m, "DOCUMENT_PREFIXES is gone — every route is back on the command-sized cap"
    return re.findall(r'"([^"]+)"', m.group(1))


def test_the_edge_accepts_every_document_the_gateway_accepts():
    from warden.config import settings

    gateway_max = settings.doc_intel_max_bytes
    edge_max = _constant("MAX_DOCUMENT_BYTES")
    needed = math.ceil(gateway_max * _BASE64_INFLATION)

    assert edge_max >= needed, (
        f"the edge caps document bodies at {edge_max:,} B but the gateway accepts "
        f"{gateway_max:,} B of file, which is {needed:,} B once base64-encoded. "
        "Every file between those two numbers gets a 413 warden never issued."
    )


def test_filter_is_treated_as_a_document_route():
    """`FilterRequest.file_base64` is why: /filter carries whole files."""
    from warden.schemas import FilterRequest

    assert "file_base64" in FilterRequest.model_fields, (
        "if /filter no longer carries files, this test and DOCUMENT_PREFIXES "
        "should both say so — do not just delete the assertion below"
    )
    prefixes = _document_prefixes()
    assert "/filter" in prefixes, f"/filter is not in DOCUMENT_PREFIXES: {prefixes}"


@pytest.mark.parametrize("route", ["/document-intel/", "/doc-converter"])
def test_the_document_routers_are_covered(route):
    assert route in _document_prefixes()


def test_the_two_caps_are_still_distinct():
    """A command body has no business being 70 MB; collapsing the two caps into
    one would pass the test above while removing the gate it exists to keep."""
    assert _constant("MAX_BODY_BYTES") < _constant("MAX_DOCUMENT_BYTES")
