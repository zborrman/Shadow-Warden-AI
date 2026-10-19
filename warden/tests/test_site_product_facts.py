"""
warden/tests/test_site_product_facts.py

`site/src/data/product.ts` is where the site gets the numbers it states about
the product. Each value names its source; these tests read that source, so a
number cannot drift the way the hand-typed copies did — "30 tools" stayed on
five pages while SOVA grew to 92, the footer on every page said "14-layer"
against a 9-layer security model, and the enterprise guide said "11 Docker
services" for a 24-service stack. Found 2026-10-19 while bringing the site up
to v7.10.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

_REPO = Path(__file__).resolve().parents[2]
_PRODUCT = _REPO / "site" / "src" / "data" / "product.ts"
_SITE = _REPO / "site" / "src"


def _field(name: str) -> str:
    m = re.search(rf"^\s*{name}:\s*\"?([^\",\n]+)\"?,", _PRODUCT.read_text(encoding="utf-8"), re.M)
    assert m, f"product.ts no longer declares {name}"
    return m.group(1).strip()


def test_sova_tool_count_matches_the_dispatch_table() -> None:
    from warden.agent.tools import TOOL_HANDLERS

    assert int(_field("sovaTools")) == len(TOOL_HANDLERS)


def test_sova_model_matches_the_default_in_code() -> None:
    src = (_REPO / "warden" / "agent" / "sova.py").read_text(encoding="utf-8")
    m = re.search(r'_MODEL\s*=\s*os\.getenv\("SOVA_MODEL",\s*"claude-opus-(\d+)-(\d+)"\)', src)
    assert m, "sova.py no longer sets a claude-opus default for SOVA_MODEL"
    assert _field("sovaModel") == f"Claude Opus {m.group(1)}.{m.group(2)}"


def test_service_count_matches_compose() -> None:
    services = yaml.safe_load((_REPO / "docker-compose.yml").read_text(encoding="utf-8"))["services"]
    assert int(_field("services")) == len(services)


def test_endpoint_count_matches_the_published_spec() -> None:
    spec = json.loads((_REPO / "site" / "public" / "openapi.json").read_text(encoding="utf-8"))
    assert int(_field("endpoints")) == len(spec["paths"])


def test_defense_layer_count_matches_the_security_model() -> None:
    model = (_REPO / "docs" / "security-model.md").read_text(encoding="utf-8")
    layers = {int(n) for n in re.findall(r"Layer (\d+) —", model)}
    assert layers, "security-model.md no longer numbers its layers"
    assert int(_field("defenseLayers")) == max(layers)


def _live_lines():
    """Everything that can render: pages, layouts and components (a component
    can be imported by one page and missed by a page-only scan, as Footer was)."""
    roots = [(_SITE / d, "*.astro") for d in ("pages", "layouts", "components")]
    roots.append((_REPO / "site" / "public", "*.html"))  # hand-written static pages
    for root, glob in roots:
        for p in root.rglob(glob):
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                yield f"{p.relative_to(_REPO).as_posix()}:{n}", line


# Only a defense-layer count: "3-layer decoder" is recursion depth, not this.
_LAYER_RX = re.compile(
    r"\b(\d{1,2})[- ](?:defen[cs]e layers|layer(?=[\s-]*(?:defen|pipeline|filter|security|DPI|inline|"
    r"cryptographic|real-time|guardrail|zero)))",
    re.I,
)
_TOOLS_RX = re.compile(r"\b(\d{2,3})\+? tools\b", re.I)


def test_no_page_states_a_different_layer_count() -> None:
    want = int(_field("defenseLayers"))
    wrong = [f"{loc}: {line.strip()[:100]}" for loc, line in _live_lines()
             for m in _LAYER_RX.finditer(line) if int(m.group(1)) != want]
    assert not wrong, f"layer count other than {want}:\n  " + "\n  ".join(wrong)


def test_no_page_states_a_different_sova_tool_count() -> None:
    want = int(_field("sovaTools"))
    wrong = [f"{loc}: {line.strip()[:100]}" for loc, line in _live_lines()
             if "SOVA" in line or "Opus" in line
             for m in _TOOLS_RX.finditer(line) if int(m.group(1)) != want]
    assert not wrong, "SOVA tool count typed by hand, use PRODUCT.sovaTools:\n  " + "\n  ".join(wrong)


def test_the_checks_can_fail() -> None:
    assert int(_LAYER_RX.search("gateway. 14-layer defense pipeline.").group(1)) == 14
    assert int(_TOOLS_RX.search("SOVA (30 tools, Claude Opus)").group(1)) == 30
