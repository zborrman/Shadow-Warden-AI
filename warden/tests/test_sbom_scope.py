"""
warden/tests/test_sbom_scope.py

**The supply-chain chain attests an image production does not run.**

`sbom-sign` builds `warden/`, pushes it to GHCR, signs it keylessly, attaches a
signed in-toto SBOM attestation and verifies that attestation before going
green. All of that is real. What it covers is the GHCR image.

The `deploy` job does something else: it SSHes to the VPS, `git pull`s, and runs
`docker compose build`. `docker-compose.yml`'s `warden` service has a `build:`
stanza and **no `image:`**, so the container serving production traffic is a
separate build of the same commit, produced on the host — with no signature, no
SBOM and no provenance of its own.

Same source, different artefact. A green "SBOM + Image Signing" therefore does
not mean the running container is attested, and this file exists so nobody has
to reconstruct that from two files a thousand lines apart.

The tests pin the two facts that keep the claim honest:

1. both builds are fed by the **same Dockerfile and context**, so the SBOM at
   least describes the same source tree the host builds from;
2. the compose service is still host-built, so the moment somebody pins
   `image: ghcr.io/...` the scope note above stops being true and this test
   says so.
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_COMPOSE = _REPO / "docker-compose.yml"
_CI = _REPO / ".github" / "workflows" / "ci.yml"


# Parsed as text, not with PyYAML: it is a pin in constraints.txt, not an
# installed dependency of the test env, and an `importorskip` would turn this
# whole file into a guard that silently never runs. The other compose checks in
# this suite read the file the same way.

def _block(text: str, header: str, indent: int) -> str:
    """The lines under `header` up to the next sibling at the same indent."""
    pad = " " * indent
    start = re.search(rf"^{pad}{re.escape(header)}:\s*$", text, re.M)
    assert start, f"{header!r} not found at indent {indent}"
    rest = text[start.end():]
    nxt = re.search(rf"^{pad}\S", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def _compose_warden() -> str:
    return _block(_COMPOSE.read_text(encoding="utf-8"), "warden", 2)


def _sbom_build_context() -> str:
    job = _block(_CI.read_text(encoding="utf-8"), "sbom-sign", 2)
    m = re.search(r"uses: docker/build-push-action.*?context:\s*(\S+)", job, re.S)
    assert m, "sbom-sign no longer has a docker/build-push-action step with a context"
    return m.group(1)


def test_attested_build_and_deployed_build_share_a_context():
    """If these diverge, the SBOM stops describing the source the host builds."""
    ci_context = _sbom_build_context().strip("./")
    m = re.search(r"context:\s*(\S+)", _compose_warden())
    assert m, "the warden service has no build context"
    compose_context = m.group(1).strip("./")
    assert ci_context == compose_context, (
        f"sbom-sign scans `{ci_context}` but production builds `{compose_context}` — "
        "the attestation now describes a different tree than the one that ships"
    )


def test_compose_warden_is_still_host_built():
    """The scope note in ci.yml claims production runs an unsigned host build.

    The day that stops being true — someone pins `image: ghcr.io/...@sha256:` —
    this test fails, and the note plus `docs/security-model.md` must be updated
    to say the running artefact IS the attested one. Failing here is good news;
    it just must not pass silently.
    """
    svc = _compose_warden()
    assert re.search(r"^    build:\s*$", svc, re.M), (
        "warden no longer builds from source — update the scope note"
    )
    assert not re.search(r"^    image:", svc, re.M), (
        "warden now pins an image. If it is the signed GHCR digest, production is "
        "finally running the attested artefact — update the SCOPE comment in "
        "ci.yml's sbom-sign job and docs/security-model.md, then update this test. "
        "If it is anything else, that is a supply-chain regression."
    )


def test_the_scope_warning_is_present_in_the_workflow():
    """A comment is the only thing standing between a green job and a false
    conclusion, so treat it as load-bearing."""
    ci = _CI.read_text(encoding="utf-8")
    assert "Production does not run that image" in ci, (
        "the SBOM scope warning was removed from ci.yml — without it a green "
        "`SBOM + Image Signing` reads as production coverage, which it is not"
    )


def test_sbom_generation_is_not_a_single_unretried_download():
    """The job failed on main on 2026-08-11 with `HTTP status=000` fetching the
    syft release, taking the SLSA job down with it. Losing supply-chain evidence
    to one flaky download must not be possible again."""
    ci = _CI.read_text(encoding="utf-8")
    install = re.search(r"- name: Install syft \(retried\).*?(?=\n      - name:)", ci, re.S)
    assert install, "the retried syft install step is gone"
    body = install.group(0)
    assert "for attempt in" in body, "the retry loop is gone"
    assert "exit 1" in body, (
        "a failed install must fail the job — publishing a signed image with no "
        "bill of materials is the outcome this whole step exists to prevent"
    )
