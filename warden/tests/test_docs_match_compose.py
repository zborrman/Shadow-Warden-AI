"""warden/tests/test_docs_match_compose.py — SW-14.

The service inventory in CLAUDE.md and README.md must match docker-compose.yml.

Both said "Eleven Docker services" and listed `dashboard` on port 8501. The
stack has 24 services; `dashboard` is the Next.js SOC UI on 3002, and the
Streamlit UI is a different service called `admin` on 8502. The architecture
diagram in CLAUDE.md pointed the Streamlit dashboard at 8501 as well.

None of that was ever true of the main stack. 8501 is the SMB profile's
dashboard port (`docker-compose.smb.yml`), which is a different file and, until
OB-F22, a port published on every interface — so the documentation was
describing one deployment while claiming to describe another.

CLAUDE.md is loaded into the context of every session in this repo, so a wrong
port there is repeated into work rather than merely misread once.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[2]
_COMPOSE = _ROOT / "docker-compose.yml"
_DOCS = ("CLAUDE.md", "README.md")

_NUMBER_WORDS = {
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
    "twenty-one": 21, "twenty-two": 22, "twenty-three": 23,
    "twenty-four": 24, "twenty-five": 25, "twenty-six": 26,
}


def _services() -> dict:
    return (yaml.safe_load(_COMPOSE.read_text(encoding="utf-8")) or {}).get("services", {})


def _declared_ports(service: dict) -> set[str]:
    """Ports a service exposes or publishes, as strings."""
    out: set[str] = set()
    for entry in list(service.get("expose") or []) + list(service.get("ports") or []):
        text = str(entry) if not isinstance(entry, dict) else str(entry.get("target", ""))
        for part in str(text).split(":"):
            if part.strip().isdigit():
                out.add(part.strip())
    return out


def test_the_service_count_in_the_docs_is_the_real_one() -> None:
    actual = len(_services())
    wrong: list[str] = []

    for name in _DOCS:
        text = (_ROOT / name).read_text(encoding="utf-8")
        for m in re.finditer(r"\b([A-Za-z-]+|\d+)\s+Docker services\b", text):
            token = m.group(1).lower()
            claimed = _NUMBER_WORDS.get(token, int(token) if token.isdigit() else None)
            if claimed is not None and claimed != actual:
                wrong.append(f"{name}: claims {m.group(1)} Docker services; compose defines {actual}")

    assert not wrong, "\n  ".join(["the docs miscount the stack:", *wrong])


def test_a_documented_service_port_is_that_service_s_port() -> None:
    """`name` (port) in prose has to agree with the compose file.

    The drift that prompted this was `dashboard` (8501): a real service, a real
    port, belonging to neither each other nor the same file.
    """
    services = _services()
    wrong: list[str] = []

    for name in _DOCS:
        text = (_ROOT / name).read_text(encoding="utf-8")
        # Only a parenthesis holding ports and nothing else. `(03:30 UTC)` is a
        # cron time, not a port, and matching it made the guard cry wolf on its
        # first run.
        for m in re.finditer(r"`(?P<svc>[a-z][a-z0-9-]*)`\s*\((?P<port>\d{2,5})(?:/\d{2,5})*\)", text):
            svc, port = m.group("svc"), m.group("port")
            if svc not in services:
                continue
            declared = _declared_ports(services[svc])
            if declared and port not in declared:
                wrong.append(
                    f"{name}: documents `{svc}` on {port}; compose gives it "
                    f"{', '.join(sorted(declared))}"
                )

    assert not wrong, "\n  ".join(["documented ports do not match compose:", *wrong])
