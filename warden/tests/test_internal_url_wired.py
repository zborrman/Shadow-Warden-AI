"""
warden/tests/test_internal_url_wired.py

`WARDEN_INTERNAL_URL` defaults to `http://localhost:8001`, which is correct in
exactly one place — inside the gateway container. Anywhere else it resolves to
nothing, and the code that reads it fails in whatever way that module happens to
fail.

It was set on `portal` alone. `settings_watcher` runs in `arq-worker`, so its
canary probe never reached the filter for the life of the deployment, and because
"probe failed" was indistinguishable from "jailbreak not blocked" it paged
`A known jailbreak was NOT blocked by the filter pipeline` 35 times a day. The
Streamlit billing page in `analytics` reads it too.

This is the compose half of the guard: any service that runs Warden code and is
not the gateway must set the variable explicitly. The env-var-set-for-one-service
class already has its own memory entry; this is the ratchet.
"""
from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

import pytest

yaml = pytest.importorskip("yaml")

_COMPOSE = Path(__file__).resolve().parents[2] / "docker-compose.yml"

#: The gateway itself — `localhost:8001` is the correct value there.
_GATEWAY = "warden"

#: Services that run code reading `settings.warden_internal_url`. Keep this in
#: step with the consumers: analytics/pages/9_Billing.py, workers/settings_watcher.py.
_MUST_SET = {"arq-worker", "analytics", "portal"}


def _services() -> dict:
    if not _COMPOSE.exists():
        pytest.skip("docker-compose.yml not present in this checkout")
    return (yaml.safe_load(_COMPOSE.read_text(encoding="utf-8")) or {}).get("services", {})


def _env_keys(svc: dict) -> dict[str, str]:
    env = svc.get("environment") or []
    if isinstance(env, dict):
        return {k: str(v) for k, v in env.items()}
    out = {}
    for item in env:
        if isinstance(item, str) and "=" in item:
            k, v = item.split("=", 1)
            out[k] = v
    return out


#: Hosts that only ever resolve to the container itself.
_LOOPBACK = {"localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"}


def _effective(value: str) -> str:
    """Resolve a compose value to what the container would actually receive.

    `${VAR:-default}` and `${VAR-default}` fall back to the default whenever the
    host environment does not set VAR, which is the normal case on this
    deployment — so the default IS the effective value, and a substring check
    against the raw `${...}` text would happily pass a default of
    `http://localhost:8001`. `${VAR}` with no default resolves to empty, which is
    worse than unset: it silently overrides the code's own fallback.
    """
    v = value.strip()
    m = re.fullmatch(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-(.*))?\}", v)
    if m:
        return (m.group(2) or "").strip()
    return v


def _host(url: str) -> str:
    return (urlparse(url).hostname or "").strip().lower()


@pytest.mark.parametrize("name", sorted(_MUST_SET))
def test_service_sets_the_internal_url(name: str) -> None:
    services = _services()
    if name not in services:
        pytest.skip(f"service {name} not defined")
    env = _env_keys(services[name])
    assert "WARDEN_INTERNAL_URL" in env, (
        f"{name} runs Warden code that calls the gateway through "
        f"WARDEN_INTERNAL_URL, and does not set it. It would fall back to "
        f"http://localhost:8001, which inside that container is nothing."
    )

    effective = _effective(env["WARDEN_INTERNAL_URL"])
    assert effective, (
        f"{name} sets WARDEN_INTERNAL_URL to an interpolation with no default, so "
        f"it resolves to an empty string whenever the host env does not define it "
        f"— which overrides the code's own fallback with nothing."
    )
    assert _host(effective) not in _LOOPBACK, (
        f"{name} resolves WARDEN_INTERNAL_URL to {effective!r}, a loopback host. "
        f"Only the gateway container can reach the gateway that way."
    )


def test_gateway_is_not_required_to_set_it() -> None:
    """The default is right for the gateway; this documents why it is exempt."""
    services = _services()
    if _GATEWAY not in services:
        pytest.skip("gateway service not defined")
    env = _env_keys(services[_GATEWAY])
    value = _effective(env.get("WARDEN_INTERNAL_URL", "http://localhost:8001"))
    assert _host(value) in _LOOPBACK | {"warden"}
