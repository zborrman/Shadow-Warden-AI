"""warden/tests/test_dashboard_middleware_fail_closed.py — SW-15.

The SOC dashboard's middleware must not admit everyone when it has no key.

`dashboard/src/middleware.ts` opened with:

    const key = process.env.DASHBOARD_API_KEY;
    if (!key) return NextResponse.next(); // no auth configured -> open access

and `docker-compose.yml` passes `DASHBOARD_API_KEY=${DASHBOARD_API_KEY:-}`, so
an operator whose `.env` omits the line gets an empty string, not a missing
container variable. The dashboard then serves the whole SOC UI — every request,
every verdict, the tenant list — to anyone who can reach port 3002.

Two things make this worth a gate rather than a comment.

The two halves of the same login already disagreed. `app/api/auth/route.ts`
rejects every attempt when the key is unset (`!expected` -> 401), and
`app/api/warden/[...path]/route.ts` refuses to proxy at all. So the login form
was shut and the front door was open, in one codebase, deliberately in both
cases.

And this is the same contract as the SMB dashboard fixed in OB-F22, where an
unset `DASHBOARD_PASSWORD_HASH` meant dev mode and admitted everyone. Finding
the identical default twice in one product is what makes it a class rather than
an oversight.

Production sets the variable, so this was a loaded trap rather than an open
door. Traps are worth disarming before they fire.

These are structural assertions: the dashboard has no JavaScript test harness
and CI only builds and type-checks it.
"""
from __future__ import annotations

import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_MIDDLEWARE = _ROOT / "dashboard" / "src" / "middleware.ts"
_COMPOSE = _ROOT / "docker-compose.yml"

#: The one escape hatch, named so it cannot be turned on by accident. The
#: gateway's own flag is `ALLOW_UNAUTHENTICATED`; the dashboard takes a distinct
#: name so a single dev variable cannot open two different doors at once.
OPT_OUT = "DASHBOARD_ALLOW_UNAUTHENTICATED"


def _code() -> str:
    """Middleware source with comments stripped — a promise in prose is not one."""
    src = _MIDDLEWARE.read_text(encoding="utf-8")
    src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
    return "\n".join(
        line for line in src.splitlines() if not line.lstrip().startswith("//")
    )


def _missing_key_branch(code: str) -> str:
    """The body of `if (!key) { ... }`, brace-matched.

    The first version of this helper took a fixed 400 characters after the
    `DASHBOARD_API_KEY` read and asserted `NextResponse.next()` did not appear
    in them. That flagged the *corrected* code, because the opt-out's `next()`
    lives in that window and is perfectly legitimate. A check that cannot tell
    a guarded return from an unguarded one is testing the spelling, not the
    property.
    """
    start = code.index("if (!key)")
    i = code.index("{", start)
    depth = 0
    for j in range(i, len(code)):
        if code[j] == "{":
            depth += 1
        elif code[j] == "}":
            depth -= 1
            if depth == 0:
                return code[i:j + 1]
    return code[i:]


def test_a_missing_key_does_not_mean_open_access() -> None:
    code = _code()
    assert "if (!key)" in code, (
        "middleware.ts no longer branches on a missing DASHBOARD_API_KEY at "
        "all; check what it does instead before deleting this test."
    )

    branch = _missing_key_branch(code)

    assert "503" in branch, (
        "the missing-key branch does not refuse the request. An unconfigured "
        "dashboard must serve nothing rather than everything:\n" + branch
    )
    assert OPT_OUT in branch or "OPT_OUT" in branch, (
        f"the missing-key branch has no {OPT_OUT} escape hatch. A guard with no "
        "way to run locally gets deleted rather than configured."
    )

    # Any early return in that branch has to sit behind the opt-out.
    before_optout, _, _ = branch.partition("OPT_OUT")
    assert "NextResponse.next()" not in before_optout, (
        "the missing-key branch lets the request through before checking the "
        "opt-out, so an unconfigured dashboard is open regardless of it."
    )


def test_the_opt_out_is_an_exact_match_not_a_truthiness_check() -> None:
    """`if (process.env.X)` treats "false", "0" and "no" as on.

    An operator who writes `DASHBOARD_ALLOW_UNAUTHENTICATED=false` to be explicit
    would open the dashboard with it. The check has to be against the literal
    string.
    """
    code = _code()
    assert re.search(
        r"process\.env\." + OPT_OUT + r"\s*===\s*[\"']true[\"']", code
    ), (
        f"{OPT_OUT} is not compared to the exact string \"true\". Any non-empty "
        "value would then disable authentication, including the word 'false'."
    )


def test_the_session_compare_is_constant_time() -> None:
    """`token === key` leaks the key one byte at a time, in principle.

    The proxy handler next door already uses `timingSafeEqual` for the same
    comparison against the same secret. Two different standards for one value
    is the kind of gap that survives review because each half looks fine alone.
    """
    code = _code()
    assert not re.search(r"token\s*===\s*key", code), (
        "middleware.ts compares the session cookie with `===`, which returns "
        "early on the first differing byte. Compare in constant time, as "
        "app/api/warden/[...path]/route.ts does."
    )


def test_compose_makes_the_opt_out_visible() -> None:
    """An escape hatch nobody can find gets replaced by a worse one.

    `DASHBOARD_API_KEY=${DASHBOARD_API_KEY:-}` is why the empty-string case
    exists at all: compose turns a missing `.env` line into a present-but-empty
    variable. The opt-out belongs beside it, where whoever hits the closed door
    will look.
    """
    compose = _COMPOSE.read_text(encoding="utf-8")
    assert OPT_OUT in compose, (
        f"{OPT_OUT} is not in docker-compose.yml. An operator hitting the "
        "fail-closed 503 has nowhere to discover the flag."
    )
