"""
The SOC dashboard must not carry the gateway API key in its browser bundle
(2026-07-30).

The dashboard is entirely client-rendered, so `dashboard/src/lib/api.ts` and the
page components run in the visitor's browser. They previously called the gateway
cross-origin with no credential — `get()` sent no headers and `post()` sent a
literal `X-API-Key: ""` — so every route gated by #244/#245/#247/#248/#251
answered 401. The whole Community Hub was dead in production.

The obvious repair is the wrong one. A `NEXT_PUBLIC_*` variable is inlined into
the JavaScript Next.js serves to every visitor, so `NEXT_PUBLIC_WARDEN_API_KEY`
(which one page already read) would publish the gateway credential. The key now
lives server-side behind `dashboard/src/app/api/warden/[...path]/route.ts`.

These are structural assertions, not behavioural ones: the dashboard has no
JavaScript test harness, and CI only builds and type-checks it. They exist so
that reintroducing a browser-side credential, or turning the proxy into an open
relay, fails here rather than silently in production.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_DASH = Path(__file__).resolve().parents[2] / "dashboard" / "src"
_PROXY = _DASH / "app" / "api" / "warden" / "[...path]" / "route.ts"

pytestmark = pytest.mark.skipif(
    not _DASH.is_dir(), reason="dashboard/ not present in this checkout"
)


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8")


def test_proxy_route_exists() -> None:
    assert _PROXY.is_file(), (
        "the dashboard's server-side API proxy is gone; without it the browser "
        "has no way to reach gated gateway routes"
    )


def test_proxy_fails_closed_without_a_dashboard_session_key() -> None:
    """
    `middleware.ts` deliberately fails OPEN when `DASHBOARD_API_KEY` is unset
    ("no auth configured -> open access"). That is defensible for pages showing
    anonymous data and indefensible in front of a privileged credential, so the
    proxy re-checks the session itself and refuses when none is configured.
    """
    src = _read(_PROXY)
    assert "DASHBOARD_API_KEY" in src, "proxy no longer verifies the dashboard session"
    assert re.search(r"if\s*\(\s*!expected\s*\)\s*return false", src), (
        "proxy no longer fails closed when DASHBOARD_API_KEY is unset — an "
        "unconfigured deployment would become an anonymous authenticated relay "
        "to the gateway"
    )


def test_proxy_restricts_paths() -> None:
    """Without an allowlist this relays every route on the gateway."""
    src = _read(_PROXY)
    assert "GET_ALLOW" in src and "POST_ALLOW" in src
    assert "allow.some(" in src, "proxy no longer checks the path against an allowlist"


def test_every_verb_the_proxy_answers_has_its_own_allowlist() -> None:
    """SW-9 added DELETE. A verb without a list of its own is an open relay.

    The path check is `allow.some(...)` against whatever list the handler was
    given, so the guarantee is only as good as the argument at that call site.
    A DELETE handler that reused POST_ALLOW would accept a deletion nobody
    approved; one that reused GET_ALLOW would accept a great deal more.
    """
    src = _read(_PROXY)
    verbs = re.findall(r"export async function ([A-Z]+)\s*\(", src)
    assert verbs, "the proxy exports no HTTP handlers at all"

    for verb in verbs:
        body_start = src.index(f"export async function {verb}")
        body = src[body_start:src.index("\n}", body_start)]
        assert f"{verb}_ALLOW" in body, (
            f"the {verb} handler does not pass {verb}_ALLOW. Every verb needs "
            f"its own list — sharing one grants each verb the other's routes."
        )
        assert f"const {verb}_ALLOW" in src, f"{verb}_ALLOW is not defined"


def test_proxy_does_not_expose_the_detection_kill_switch() -> None:
    """
    `PATCH /config` retunes `semantic_threshold` for the whole gateway — the
    control that was an unauthenticated kill switch until #244. It must not be
    reachable from a shared dashboard password.
    """
    code = [
        line
        for line in _read(_PROXY).splitlines()
        if not line.lstrip().startswith(("//", "*", "/*"))
    ]
    assert not [line for line in code if "/config" in line], (
        "the live detection config is reachable through the dashboard proxy"
    )


def test_browser_code_carries_no_gateway_credential() -> None:
    """
    No `NEXT_PUBLIC_*` API key anywhere, and no hand-written `X-API-Key` header
    in client code. The one permitted exception is the onboarding page, where the
    operator types their own key to test their own gateway.
    """
    offenders: list[str] = []
    for path in _DASH.rglob("*.ts*"):
        rel = path.relative_to(_DASH).as_posix()
        if rel.startswith("app/api/"):
            continue  # server-side
        text = _read(path)
        for line in text.splitlines():
            if line.lstrip().startswith(("//", "*", "/*")):
                continue
            if "NEXT_PUBLIC_WARDEN_API_KEY" in line:
                offenders.append(f"{rel}: {line.strip()}")
            if "X-API-Key" in line and rel != "app/(soc)/onboarding/page.tsx":
                offenders.append(f"{rel}: {line.strip()}")
    assert not offenders, (
        "gateway credential material in browser-delivered code:\n  "
        + "\n  ".join(offenders)
    )


def test_api_client_calls_the_proxy() -> None:
    """
    `api.ts` must address the same-origin proxy. A direct cross-origin base URL
    means an uncredentialed call, which is how this broke.
    """
    src = _read(_DASH / "lib" / "api.ts")
    assert 'WARDEN_PROXY = "/api/warden"' in src
    assert "NEXT_PUBLIC_API_URL" not in src, (
        "api.ts is addressing the gateway directly again"
    )
