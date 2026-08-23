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

import ipaddress
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


#: Hostnames that only ever resolve to the container itself. IP forms are
#: classified rather than listed — `127.0.0.2` and `::ffff:127.0.0.1` are as
#: local as `127.0.0.1`, and an exact-string set would wave them through.
_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def _is_container_local(host: str) -> bool:
    """True when this host can only ever mean "this container"."""
    h = (host or "").strip().lower().strip("[]")
    if not h:
        return False
    if h in _LOOPBACK_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    # Unspecified (0.0.0.0, ::) is a bind address, never a destination.
    return ip.is_loopback or ip.is_unspecified or ip.is_link_local


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
    host = _host(effective)
    assert host, (
        f"{name} resolves WARDEN_INTERNAL_URL to {effective!r}, which has no host."
    )
    assert not _is_container_local(host), (
        f"{name} resolves WARDEN_INTERNAL_URL to {effective!r}, which can only ever "
        f"mean this container. Only the gateway can reach the gateway that way."
    )


def test_gateway_is_not_required_to_set_it() -> None:
    """The default is right for the gateway; this documents why it is exempt."""
    services = _services()
    if _GATEWAY not in services:
        pytest.skip("gateway service not defined")
    env = _env_keys(services[_GATEWAY])
    value = _effective(env.get("WARDEN_INTERNAL_URL", "http://localhost:8001"))
    host = _host(value)
    assert _is_container_local(host) or host == "warden"

def test_container_local_classification() -> None:
    """`127.0.0.2` is as local as `127.0.0.1`; a string set would miss it."""
    for host in ("localhost", "127.0.0.1", "127.0.0.2", "::1", "0.0.0.0", "169.254.1.1"):
        assert _is_container_local(host), host
    for host in ("warden", "10.0.0.5", "gateway.internal", ""):
        assert not _is_container_local(host), host


def test_effective_resolves_every_compose_shape() -> None:
    """What the container receives, not what the YAML says."""
    assert _effective("${V:-http://warden:8001}") == "http://warden:8001"
    assert _effective("${V-http://warden:8001}") == "http://warden:8001"
    assert _effective("${V}") == ""          # overrides the code's own fallback
    assert _effective("http://warden:8001") == "http://warden:8001"
