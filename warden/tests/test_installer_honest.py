"""
warden/tests/test_installer_honest.py

`scripts/install.sh` advertised a 14-day trial and a paid licence path. Both
POSTed to a licence server that does not exist anywhere in this repository, and
both ended at "Cannot reach license server" on every machine that tried — while
the site and the portal pointed at an install host (`install.shadow-warden-ai.com`)
that does not resolve either.

The default is now a self-hosted install that generates its own API key and
contacts nothing. `--trial` and `--license=` refuse up front, before touching
the network or asking for root, unless `--drm=` names a licence server someone
actually runs.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO / "scripts" / "install.sh"


def _bash() -> str:
    exe = shutil.which("bash")
    if not exe:  # pragma: no cover - environment-dependent
        pytest.skip("bash is not on PATH")
    return exe


@pytest.mark.parametrize("flag", ["--trial", "--license=SW-AAA-BBB-CCC"])
def test_licence_paths_refuse_instead_of_calling_a_server_that_does_not_exist(flag):
    proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [_bash(), str(_SCRIPT), flag],
        capture_output=True, text=True, timeout=30,
        env={"PATH": "/usr/bin:/bin", "DRM_ENDPOINT": "http://127.0.0.1:9/unused"},
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert "no licence server" in out, out
    assert "Requesting trial key" not in out and "Validating license key" not in out, (
        "the script reached the network step it should have refused before"
    )


def test_the_header_does_not_advertise_a_trial():
    head = _SCRIPT.read_text(encoding="utf-8").splitlines()[:14]
    offered = [ln for ln in head if "curl" in ln and ("--trial" in ln or "--license" in ln)]
    assert not offered, f"the documented one-liner offers what cannot be issued: {offered}"


def test_no_surface_points_at_an_install_host_that_does_not_resolve():
    for rel in ("site/src/components/SettingsSection.astro", "portal/src/app/settings/page.tsx"):
        assert "install.shadow-warden-ai.com" not in (_REPO / rel).read_text(encoding="utf-8"), rel


def test_the_printed_grafana_address_is_the_one_compose_publishes():
    """Grafana is bound to 127.0.0.1:3001 — the installer used to print the
    public IP on 3000, which compose has never published."""
    script = _SCRIPT.read_text(encoding="utf-8")
    assert ":3000  (Grafana)" not in script
    assert "127.0.0.1:3001" in script
