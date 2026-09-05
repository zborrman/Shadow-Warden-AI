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


def test_prose_with_an_apostrophe_does_not_blind_the_scanner() -> None:
    """CodeRabbit, round 1 on #443: the third fail-open found in this guard.

    Every apostrophe was treated as a string opener, so JSX text like
    `doesn't` began a "string" that ran to the next apostrophe or to end of
    file. Everything in that span was blanked and no rule could match inside
    it — including a real violation placed after `doesn't` in
    `login/page.tsx`. A guard that goes quiet on ordinary English prose fails
    open in the quietest way there is.
    """
    src = "\n".join([
        "export default function P() {",
        "  return <p>the operator doesn't see this</p>;",
        "}",
        "const s = stats ?? MOCK_STATS;",
    ])
    problems = check_file(_FAKE, src)
    # Assert the *specific* finding, not merely that something was reported.
    # Asserting non-emptiness passed even with `_opens_a_string` stubbed to
    # True, because the unterminated-quote rule below then fired instead: two
    # fixes covering for each other, and neither actually exercised.
    assert any("MOCK_STATS" in p for p in problems), (
        f"check_file() missed the violation that followed an apostrophe in JSX "
        f"text; the scanner blanked the rest of the file. Got: {problems}"
    )

    # A string really does open after whitespace, and must still be blanked.
    assert not check_file(
        _FAKE, "function f() { return '?? MOCK_STATS'; }"
    ), "a quoted string is not code and must not be scanned as such"


def test_a_file_the_scanner_cannot_parse_is_reported_not_passed() -> None:
    """Fail closed: an unterminated quote means the rest went unchecked.

    If a mis-parse ever gets past `_opens_a_string`, the span after it is
    blanked and every rule passes on it silently. Saying "I could not read
    this" is the only honest outcome; reporting the file clean is the failure
    mode this whole change exists to remove.
    """
    problems = check_file(
        _FAKE, "const s = 'unterminated;\nconst t = x ?? MOCK_STATS;\n"
    )
    assert problems, "an unterminated quote was reported as a clean file"
    assert any("could not parse" in p for p in problems), (
        f"the finding does not say the file was unreadable: {problems}"
    )


def test_an_unterminated_template_is_reported_too() -> None:
    """CodeRabbit round 2 on #443: the fail-closed rule covered only quotes.

    `_scan_quote` recorded an opener that never closed; `_scan_template` did
    not. So an unterminated backtick blanked the rest of the file and the file
    was still reported clean — the same hole as the quote one, one character
    different. Fixing half of a symmetric pair is its own failure mode.

    A fallback inside `${...}` before the break must still be found, so the
    diagnostic is not masking real detection.
    """
    src = "const a = `${x ?? MOCK_STATS}`;\nconst b = `unterminated\nconst c = y ?? 42;\n"
    problems = check_file(_FAKE, src)

    assert any("could not parse" in p for p in problems), (
        f"an unterminated template literal was not reported: {problems}"
    )
    assert any("MOCK_STATS" in p for p in problems), (
        f"the interpolated fallback before the break went unfound: {problems}"
    )


def test_page_copy_is_not_mistaken_for_a_comment() -> None:
    """CodeRabbit round 4 on #443: the fifth fail-open in this guard.

    `//` and `/*` were treated as comment openers wherever they appeared, so
    ordinary page copy blanked the code around it:

        <p>/* {stats ?? MOCK_STATS} */</p>
        <p>see https://example.com {stats ?? MOCK_STATS}</p>

    JSX text cannot be told from code by inspection — `useQuery<BIUsage>(` and
    `a < b` share a shape — so the openers are narrowed to the positions this
    codebase writes comments in rather than parsed. The remaining error is
    pushed to the loud side: an unrecognised comment produces a spurious
    finding; an unrecognised piece of text would produce silence.
    """
    for copy in (
        "<p>/* {stats ?? MOCK_STATS} */</p>",
        "<p>see https://example.com {stats ?? MOCK_STATS}</p>",
        "<p>a//b {stats ?? MOCK_STATS}</p>",
    ):
        assert any("MOCK_STATS" in x for x in check_file(_FAKE, copy)), (
            f"check_file() blanked {copy!r} as a comment. That is page copy, "
            "and the fallback between the markers went unchecked."
        )

    for real in (
        "// never write: const s = stats ?? MOCK_STATS;",
        "/* MOCK_STATS was removed here */",
        "{/* MOCK_STATS was removed here */}",
        "const x = /* MOCK_STATS */ 5;",
    ):
        assert not check_file(_FAKE, real), (
            f"check_file() flagged {real!r}, which is a comment. A guard that "
            "fires on its own documentation gets switched off."
        )


def test_an_unterminated_block_comment_is_reported_too() -> None:
    """Third member of the fail-closed set, after quotes and templates.

    Each was added one at a time, and each gap was found by review rather than
    by me noticing the set was incomplete.
    """
    problems = check_file(_FAKE, "/* opened and never closed\nconst s = x ?? MOCK_STATS;\n")
    assert any("could not parse" in x for x in problems), (
        f"an unterminated block comment was not reported: {problems}"
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
