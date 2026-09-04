"""warden/tests/test_dashboard_honesty.py — SW-10.

The enforcement half of `warden/hooks/dashboard_honesty.py`. The logic lives in
the hook so pre-commit can run it locally; the gate lives here because CI does
not run pre-commit — `.github/workflows/ci.yml` has no pre-commit step, so a
hook-only guard is advisory, skippable with `--no-verify`, and therefore
exactly the kind of check that reports nothing.

Observed red before the fix, on 2026-09-05: sixteen findings across six files
(`compliance`, `events`, `intelligence`, `overview`, `roi`, `smb`). That order
matters and is the reason SW-10 is written first. A guard authored against
already-corrected code has never been seen failing, so nothing establishes that
it can fail — which is how OB-F21's own guard shipped broken.

Two of its own blind spots showed up in that red run, because the red list did
not match the defects already known to be there:

  * whole backtick strings were being blanked, and all three of the ROI page's
    fallbacks live inside `${...}` interpolations;
  * the `Math.max` argument scan stopped at the first comma, which is where the
    fabricated argument always is.
"""
from __future__ import annotations

from pathlib import Path

from warden.hooks.dashboard_honesty import (
    DASHBOARD_SRC,
    NEUTRAL_NUMBERS,
    check_file,
    run,
)

_FAKE = Path("dashboard/src/app/(soc)/x/page.tsx")


def test_the_dashboard_does_not_invent_data() -> None:
    """The whole guard, as a merge gate."""
    problems = run()
    assert not problems, (
        "A dashboard that fills a dead API's gap with plausible numbers is "
        "worse than one that goes blank — the operator cannot tell which they "
        "are looking at:\n  " + "\n  ".join(problems)
    )


def test_a_mock_is_rejected_in_every_spelling_but_placeholder_data() -> None:
    """Allow-list the two legitimate positions; do not deny one operator.

    The plan for this guard said to look for `?? MOCK_`. That is one spelling.
    `||`, a ternary, `initialData:` and a bare render all put the same
    fabrication on the same screen, and `initialData: MOCK_STATS` was live on
    the overview page — it seeds React Query's cache as though the value had
    been fetched, so the query reports success and never enters an error state.
    """
    for spelling in (
        "const s = stats ?? MOCK_STATS;",
        "const s = stats || MOCK_STATS;",
        "const s = stats ? stats : MOCK_STATS;",
        "useQuery({ queryFn: api.stats, initialData: MOCK_STATS });",
        "return <Chart data={MOCK_STATS} />;",
        "const rows = data?.rows ?? PLACEHOLDER_STANDARDS;",
    ):
        assert check_file(_FAKE, spelling), (
            f"check_file() accepted {spelling!r}. Every one of these renders "
            "invented data after the request has resolved; only the operator "
            "differs."
        )

    assert not check_file(_FAKE, "useQuery({ placeholderData: MOCK_STATS });")
    assert not check_file(
        _FAKE, "useQuery({ placeholderData: { total: MOCK_EVENTS.length, events: MOCK_EVENTS } });"
    )
    assert not check_file(_FAKE, "const MOCK_STATS: StatsResponse = { total: 0 };")


def test_an_interpolated_fallback_is_not_hidden_by_its_quotes() -> None:
    """`${...}` is code, not string text — and it is where the ROI page hid.

    The first stripper blanked backtick strings whole, so the guard came back
    clean on a page already known to be broken. Any check that cannot see
    inside a template literal cannot see a React codebase.
    """
    src = 'const sub = `${live?.shadow_ban.count ?? calc.shadowBans} banned`;'
    assert check_file(_FAKE, src), (
        "check_file() missed a fallback inside a template interpolation. Three "
        "of the four ROI defects were written exactly this way."
    )
    assert not check_file(_FAKE, 'const label = `total ?? MOCK_STATS is fine as prose`;')


def test_a_clamp_reads_past_its_first_argument() -> None:
    """`Math.max(measured, fabricated)` — the fabrication is never argument one.

    A figure that by construction cannot fall below a calculator's guess is not
    a measurement. The ROI headline was floored this way, so with a live API
    returning $0 it still displayed the calculator's number.
    """
    assert check_file(
        _FAKE, "const t = Math.max(live.total_estimated_roi_usd, calc.total_roi);"
    ), (
        "check_file() accepted a measured value clamped against an estimate. "
        "The scan stopped at the first comma, which is where the measured half "
        "always is."
    )
    assert not check_file(_FAKE, "const pct = Math.min(quota.pct_used ?? 0, 100);")
    assert not check_file(
        _FAKE, "const s = Math.round(d.themes[t]?.implemented ?? 0) / Math.max(d.total ?? 1, 1);"
    )


def test_zero_and_one_stay_available_as_empty_states() -> None:
    """The numeric rule has to leave the honest default alone.

    44 uses of `?? 0` in the tree mean "no data"; `?? 1` is the safe divisor.
    A rule that flagged those would be turned off within a week, and a guard
    that is off is the same as a guard that is absent.
    """
    assert set(NEUTRAL_NUMBERS) == {"0", "1"}
    for neutral in ("const n = d?.total ?? 0;", "const n = Math.max(d?.total ?? 1, 1);"):
        assert not check_file(_FAKE, neutral)

    for invented in ("const usd = roi?.total_usd ?? 1_420_000;", "const n = p?.standards.length ?? 5;"):
        assert check_file(_FAKE, invented), (
            f"check_file() accepted {invented!r}. $1.42M shipped in a 56px "
            "'Estimated Savings' card whenever the ROI endpoint was down."
        )


def test_a_comment_about_this_rule_does_not_trip_it() -> None:
    """The guard's own explanatory comments must not be findings."""
    assert not check_file(_FAKE, "// never write: const s = stats ?? MOCK_STATS;\n")
    assert not check_file(_FAKE, "/* MOCK_STATS was removed here */\n")
    assert not check_file(_FAKE, 'const url = "https://api.example.com/x";\n')


def test_the_guard_has_something_to_check() -> None:
    """A green run on a missing directory would prove nothing."""
    assert DASHBOARD_SRC.is_dir(), (
        f"{DASHBOARD_SRC} is gone. This guard reads the dashboard sources "
        "directly; without them it is green by vacuum."
    )
    assert any(DASHBOARD_SRC.rglob("*.tsx"))
