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

import json
import math
import re
import shutil
import subprocess
import textwrap
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


# ── The gate, executed rather than read ──────────────────────────────────────
#
# The assertions above pin the constants. They do not pin the line that *uses*
# them: reverting the size check to the flat `MAX_BODY_BYTES` leaves every
# constant in place and passes all five. That mutation was found by running it,
# which is why the rest of this file runs the Worker instead of reading it.


def _node() -> str:
    exe = shutil.which("node")
    if not exe:  # pragma: no cover - environment-dependent
        pytest.skip("node is not on PATH; cannot execute the preflight worker")
    return exe


def _preflight(cases: list[dict]) -> list[dict]:
    """Run `index.js` under node against request descriptions, return verdicts.

    Real `Request` objects, not stand-ins: the pass-through branch ends in
    `new Request(request, { headers })`, which a plain object cannot satisfy —
    it throws into the Worker's outermost catch and the request is allowed
    through by the fail-open, not by the gate. `console.error` is captured for
    exactly that reason, because otherwise a crashed gate and a working one are
    the same observation. (node keeps a caller-set `content-length`, where a
    browser would strip it as a forbidden header.)
    """
    script = textwrap.dedent(
        f"""
        import worker from {json.dumps(_WORKER.as_uri())};

        let failedOpen = false;
        console.error = () => {{ failedOpen = true; }};
        globalThis.fetch = async () => new Response("origin", {{ status: 299 }});

        const cases = {json.dumps(cases)};
        const out = [];
        for (const c of cases) {{
          failedOpen = false;
          const req = new Request(
            "https://api.shadow-warden-ai.com" + c.path,
            {{ method: c.method, headers: c.headers }},
          );
          const res = await worker.fetch(req, {{}}, {{}});
          out.push({{ name: c.name, status: res.status, failed_open: failedOpen }});
        }}
        process.stdout.write(JSON.stringify(out));
        """
    ).strip()

    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [_node(), "--input-type=module", "--eval", script],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if proc.returncode != 0:  # pragma: no cover - surfaces a real breakage
        pytest.fail(f"node failed running the preflight worker:\n{proc.stderr}")
    return json.loads(proc.stdout)


_JSON = {"content-type": "application/json"}


def test_the_size_gate_is_route_aware_when_it_runs():
    """A 2 MB body: rejected as a command, accepted as a document.

    This is the assertion the constant-pinning tests cannot make. It fails if
    the check is reverted to the flat cap, which is how the gap was found.
    """
    two_mb = str(2 * 1024 * 1024)
    verdicts = {
        v["name"]: v
        for v in _preflight(
            [
                {
                    "name": "command",
                    "path": "/agent/sova",
                    "method": "POST",
                    "headers": {**_JSON, "content-length": two_mb},
                },
                {
                    "name": "document",
                    "path": "/filter",
                    "method": "POST",
                    "headers": {**_JSON, "content-length": two_mb},
                },
                {
                    "name": "document_far_over",
                    "path": "/filter",
                    "method": "POST",
                    "headers": {**_JSON, "content-length": str(100 * 1024 * 1024)},
                },
            ]
        )
    }

    assert verdicts["command"]["status"] == 413, "a 2 MB command body should not reach the origin"
    assert verdicts["document"]["status"] != 413, (
        "a 2 MB document was rejected at the edge — /filter accepts 50 MB of "
        "base64 file at the gateway, so this 413 is one warden never issued"
    )
    assert not verdicts["document"]["failed_open"], (
        "the document passed only because the Worker threw and fell open — "
        "that is not the gate working"
    )
    assert verdicts["document_far_over"]["status"] == 413, (
        "the document route must still be capped, just higher"
    )
