"""warden/hooks/dashboard_honesty.py — the SOC dashboard must not invent numbers.

Five of the twenty-six dashboard pages substituted fabricated values for live
data whenever the API was unreachable, and did it on the *permanent* render
path — not while loading. `lib/api.ts:18` throws on a non-200, so React Query
correctly enters an error state; the pages then threw that state away on the
next line:

    const events = raw?.events ?? MOCK_EVENTS;      // events
    const s      = stats ?? MOCK_STATS;             // overview
    const savedUsd = roiData?.total_estimated_roi_usd ?? 1_420_000;

An operator looking at a dead gateway saw twenty plausible security events, a
block rate, and $1.42M of "Estimated Savings" — visually indistinguishable from
the real thing. This is the same class as the site's "2,847 registered agents",
published off an unreachable API, and as the ROI floor below.

What this checks, and why each rule is shaped the way it is:

  1. A mock-family identifier (MOCK_*, PLACEHOLDER_*, DEMO_*, ...) may appear
     ONLY in its own declaration or inside a `placeholderData:` value. This is
     an allow-list on purpose. Rejecting the one spelling I had in mind — `??`
     — would leave `||`, a ternary, `initialData:` and a direct render green.
     OB-F22 shipped exactly that mistake four times before it was caught.
  2. A `??` fallback to a numeric literal other than 0 or 1 is an invented
     magnitude. 0 and 1 are "nothing to show" and a safe divisor; 1_420_000 is
     a claim. Measured against the tree: 44 uses of `?? 0` and two of anything
     else, both of them defects.
  3. A `??` fallback to a client-side estimate (`calc.*`, `estimate*.`) puts a
     model's output where a measurement belongs, under the measurement's label.
  4. `Math.max`/`Math.min` may not clamp a measured value against a fabricated
     one. A number that by construction cannot read below a calculator's guess
     is not a measurement of anything.

What it does NOT see, stated plainly rather than implied away: a fabricated
number written as a ternary alternative (`s.total > 0 ? real : 95.4`). Catching
that would mean flagging every numeric literal in a ternary, and the codebase
is full of legitimate ones — thresholds, chart geometry, IBM breach constants.
Those were removed by hand in this change; a regression there is not gated.
Rules 1-4 are.

Run directly (pre-commit) or via warden/tests/test_dashboard_honesty.py, which
is what actually gates a merge — CI does not run pre-commit.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_SRC = _ROOT / "dashboard" / "src"

#: Prefixes that name invented data. Adding one here is free; the point is that
#: the *usage* rule below is an allow-list, so a name nobody thought to prefix
#: is still caught by rules 2-4 when it is used as a fallback.
MOCK_PREFIXES: tuple[str, ...] = (
    "MOCK", "PLACEHOLDER", "DEMO", "SAMPLE", "FAKE", "DUMMY", "STUB", "EXAMPLE",
)

_MOCK_NAME = re.compile(r"\b(?:" + "|".join(MOCK_PREFIXES) + r")_[A-Z0-9_]+\b")

#: Numeric `??` fallbacks that mean "nothing to show" rather than a claim.
#: 0 is an empty count; 1 is the safe divisor in `Math.max(total ?? 1, 1)`.
NEUTRAL_NUMBERS: frozenset[str] = frozenset({"0", "1"})

_NUMERIC_RHS = re.compile(r"^[0-9][0-9_]*(?:\.[0-9]+)?$")

#: A locally computed estimate. `calc` is the ROI calculator's result object;
#: the rest are names the same idea tends to arrive under.
_ESTIMATE_RHS = re.compile(
    r"\b(?:calc|calculated|estimate|estimated|projected|simulated|synthetic)"
    r"[A-Za-z0-9_]*\s*[.\[]"
)


def _scan_quote(
    src: str, out: list[str], i: int, quote: str, unclosed: list[int],
    blank_strings: bool = True,
) -> int:
    """Blank a string literal. Record the offset if it never closes.

    Running to end of file means the scan mis-read something as a quote, and
    everything after it was blanked unchecked. `check_file` turns that into a
    finding rather than a silent pass — a guard that cannot parse a file must
    say so, not report it clean.
    """
    opened = i
    i += 1
    n = len(src)
    while i < n:
        if src[i] == "\\":
            if blank_strings:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
            i += 2
            continue
        if src[i] == quote:
            return i + 1
        if blank_strings and src[i] != "\n":
            out[i] = " "
        i += 1
    unclosed.append(opened)
    return i


def _scan_template(
    src: str, out: list[str], i: int, unclosed: list[int],
    blank_strings: bool = True,
) -> int:
    """Blank a template literal's text but KEEP the code inside `${...}`.

    This is not a detail. All three of `roi/page.tsx`'s fallbacks from a
    measurement to the client-side calculator live inside `${...}`:

        sub: `${live?.shadow_ban.count ?? calc.shadowBans} attackers banned`

    The first version of this stripper blanked whole backtick strings, so the
    guard's red run came back clean on the one page I already knew was broken.
    A checker whose blind spot is where the code actually lives is the failure
    this whole change is about.

    Like `_scan_quote`, it records an opener that never closes. That symmetry
    was missing for one round: the fail-closed diagnostic was added to quotes
    and not to templates, so an unterminated backtick still blanked the rest of
    a file and reported it clean — the same hole, one character different.
    """
    opened = i
    i += 1
    n = len(src)
    while i < n:
        if src[i] == "\\":
            if blank_strings:
                out[i] = " "
                if i + 1 < n:
                    out[i + 1] = " "
            i += 2
            continue
        if src[i] == "`":
            return i + 1
        if src[i] == "$" and i + 1 < n and src[i + 1] == "{":
            i = _scan_code(
                src, out, i + 2, unclosed,
                stop_on_close_brace=True, blank_strings=blank_strings,
            )
            continue
        if blank_strings and src[i] != "\n":
            out[i] = " "
        i += 1
    unclosed.append(opened)
    return i


#: A quote directly after one of these is not opening a string. In JavaScript a
#: value cannot be followed by a string literal, so `x'` is a syntax error —
#: which means an apostrophe glued to a word is prose, not code. In a `.tsx`
#: file that prose is JSX text: `doesn't`, `operator's`, `we'll`.
_VALUE_END = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$)]")


def _opens_a_string(src: str, i: int) -> bool:
    """Whether `src[i]` (a quote) begins a string literal rather than prose.

    `_scan_code` used to treat every apostrophe as an opener, so JSX text like
    `doesn't see this` started a "string" that ran to the next apostrophe — or
    to end of file. Everything in that span was blanked, and rules 1-4 could
    not match inside it. 26% of dashboard/src was being blanked, and a real
    violation placed after `doesn't` in login/page.tsx read clean.

    That is a guard that fails OPEN in the quietest possible way, which is the
    exact defect this file exists to catch. Whitespace before the quote is what
    separates `return 'x'` (an opener) from `doesn't` (not one), so no keyword
    list is needed.
    """
    return i == 0 or src[i - 1] not in _VALUE_END


#: A `//` here is not a comment opener. `https://x` and `a//b` are JSX text,
#: and blanking from there to end of line hid whatever followed.
_NOT_BEFORE_LINE_COMMENT = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$:/"
)

#: A `/*` opens a block comment only in these positions. In this codebase a
#: block comment is either `{/* ... */}` (the only JSX comment syntax there is),
#: at the start of a line, or inline after an operator. `<p>/* text */</p>` is
#: none of those — and blanking it hid `{stats ?? MOCK_STATS}` between the
#: markers, which is a fail-open written in ordinary page copy.
_BEFORE_BLOCK_COMMENT = set("{(,;=")


def _opens_a_comment(src: str, i: int) -> bool:
    """Whether `src[i:i+2]` is a comment opener rather than page text.

    Neither JSX text nor TypeScript generics can be told apart from code by
    inspection alone — `useQuery<BIUsage>(` and `a < b` share a shape — so this
    does not try to parse JSX. It narrows the openers to the positions this
    codebase actually writes comments in, and treats every other `//` or `/*`
    as text. The direction of the remaining error matters: an unrecognised
    comment produces a spurious finding, which is loud; an unrecognised piece of
    text produces a blanked region, which is silent.
    """
    if src.startswith("//", i):
        return i == 0 or src[i - 1] not in _NOT_BEFORE_LINE_COMMENT
    line_start = src.rfind("\n", 0, i) + 1
    if not src[line_start:i].strip():
        return True
    j = i - 1
    while j >= 0 and src[j] in " \t":
        j -= 1
    return j >= 0 and src[j] in _BEFORE_BLOCK_COMMENT


def _scan_code(
    src: str, out: list[str], i: int, unclosed: list[int],
    stop_on_close_brace: bool = False,
    blank_strings: bool = True,
) -> int:
    n = len(src)
    depth = 0
    while i < n:
        ch = src[i]
        if ch == "`":
            i = _scan_template(src, out, i, unclosed, blank_strings)
        elif ch in "\"'" and _opens_a_string(src, i):
            i = _scan_quote(src, out, i, ch, unclosed, blank_strings)
        elif ch in "\"'":
            i += 1
        elif src.startswith("//", i) and _opens_a_comment(src, i):
            while i < n and src[i] != "\n":
                out[i] = " "
                i += 1
        elif src.startswith("/*", i) and _opens_a_comment(src, i):
            opened = i
            while i < n and not src.startswith("*/", i):
                if src[i] != "\n":
                    out[i] = " "
                i += 1
            if i >= n:
                # Fail closed, as for an unterminated quote: the rest of the
                # file was blanked and every rule silently passed on it.
                unclosed.append(opened)
            for j in range(i, min(i + 2, n)):
                out[j] = " "
            i += 2
        elif src.startswith(("//", "/*"), i):
            i += 2
        elif ch == "{":
            depth += 1
            i += 1
        elif ch == "}":
            if stop_on_close_brace and depth == 0:
                return i + 1
            depth -= 1
            i += 1
        else:
            i += 1
    return i


def _strip_strings_and_comments(src: str) -> tuple[str, list[int]]:
    """Blank out string literals and comments, preserving offsets.

    Both directions matter. A comment explaining this very rule would otherwise
    trip it, and a URL like `https://api...` carries a `//`. Offsets are kept so
    reported line numbers still point at the real line. Template interpolations
    survive — see `_scan_template`.

    Known limit: a regex literal containing `//` would be mis-read as a comment
    and blank the rest of its line. There is none in the tree today.
    """
    out: list[str] = list(src)
    unclosed: list[int] = []
    _scan_code(src, out, 0, unclosed)
    return "".join(out), unclosed


def strip_comments(src: str) -> str:
    """Blank comments only, leaving string and JSX text intact.

    Shared with `warden/tests/test_dashboard_pricing_mirror.py`, whose scanner
    needs the opposite trade: a hardcoded price usually *is* string or JSX text,
    so blanking those would hide the thing it looks for — but a price inside a
    comment must not be flagged.

    That scanner first skipped lines starting with `//`, `*` or `/*`, which
    misses a block-comment continuation line that starts with anything else and
    misses a trailing comment entirely. Rather than grow a second, half-right
    parser beside this one, it reuses this traversal — which already knows that
    a `//` inside a string is not a comment.
    """
    out: list[str] = list(src)
    _scan_code(src, out, 0, [], blank_strings=False)
    return "".join(out)


def _value_span(text: str, start: int) -> tuple[int, int]:
    """Span of the expression beginning at `start`, up to a depth-0 delimiter."""
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (ch in ",;" or (ch == "\n" and text[start:i].strip())):
            break
        i += 1
    return start, i


def _allowed_spans(text: str) -> list[tuple[int, int]]:
    """Character ranges where a mock-family name is legitimate.

    Two of them: the declaration itself, and the value of a `placeholderData:`
    key. `placeholderData` is React Query's "show this until the real answer
    lands", and it keeps `isPlaceholderData` true so a page can tell the
    difference. `initialData` is deliberately NOT allowed — it seeds the cache
    as though it had been fetched, so the query reports success and the
    fabrication becomes indistinguishable from an answer.
    """
    spans: list[tuple[int, int]] = []
    for m in re.finditer(r"\bplaceholderData\s*:", text):
        spans.append(_value_span(text, m.end()))
    decl = re.compile(
        r"\b(?:const|let|var)\s+(?:" + "|".join(MOCK_PREFIXES) + r")_[A-Z0-9_]+\b"
    )
    for m in decl.finditer(text):
        spans.append(_value_span(text, m.start()))
    return spans


def _call_args_end(text: str, start: int) -> int:
    """End of an argument list that began just after `(`.

    `_value_span` stops at a depth-0 comma, which is right for one expression
    and wrong for a call: it truncated `Math.max(live.total, calc.total_roi)`
    to its first argument, so the clamp check never saw the fabricated half.
    """
    depth = 0
    i = start
    while i < len(text):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            if depth == 0:
                return i
            depth -= 1
        i += 1
    return i


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _rhs_after(text: str, pos: int) -> str:
    j = pos
    while j < len(text) and text[j] in " \t\n":
        j += 1
    a, b = _value_span(text, j)
    return text[a:b].strip()


def check_file(path: Path, src: str) -> list[str]:
    rel = path.relative_to(_ROOT).as_posix() if path.is_absolute() else path.as_posix()
    text, unclosed = _strip_strings_and_comments(src)
    problems: list[str] = []

    # Fail closed. An unterminated quote means the scanner mis-parsed and
    # blanked the rest of the file, so every rule below silently passed on
    # whatever followed. Report that instead of reporting the file clean.
    for offset in unclosed:
        problems.append(
            f"{rel}:{_line_of(text, offset)}: this guard could not parse the "
            f"file past this quote, so nothing after it was checked. Rather "
            f"than report the file clean, it reports that it cannot see. If "
            f"the quote is prose rather than code, `_opens_a_string` needs to "
            f"know about the shape it appears in."
        )

    allowed = _allowed_spans(text)
    for m in _MOCK_NAME.finditer(text):
        if any(a <= m.start() < b for a, b in allowed):
            continue
        problems.append(
            f"{rel}:{_line_of(text, m.start())}: {m.group(0)} is used outside its "
            f"declaration and outside a `placeholderData:` value. Fabricated data "
            f"may seed a *loading* view; once the request has resolved, an error "
            f"has to render as an error. Branch on `isError`/`!data` and say the "
            f"data is unavailable, the way "
            f"components/ui/community-recommendations.tsx does."
        )

    for m in re.finditer(r"\?\?", text):
        rhs = _rhs_after(text, m.end())
        line = _line_of(text, m.start())
        if _NUMERIC_RHS.match(rhs) and rhs.replace("_", "") not in NEUTRAL_NUMBERS:
            problems.append(
                f"{rel}:{line}: `?? {rhs}` invents a magnitude when the API gives "
                f"nothing back. 0 renders as 'no data'; a specific number renders "
                f"as a finding. Show the empty state instead."
            )
        elif _ESTIMATE_RHS.search(rhs):
            problems.append(
                f"{rel}:{line}: `?? {rhs}` falls back from a measurement to a "
                f"client-side estimate, under the measurement's own label. Keep "
                f"the estimate in its own block, labelled as a model."
            )

    for m in re.finditer(r"\bMath\.(max|min)\s*\(", text):
        args = text[m.end():_call_args_end(text, m.end())]
        if _MOCK_NAME.search(args) or _ESTIMATE_RHS.search(args):
            problems.append(
                f"{rel}:{_line_of(text, m.start())}: `Math.{m.group(1)}` clamps a "
                f"measured value against a fabricated one, so the figure can never "
                f"read below the fabrication. That is not a measurement of "
                f"anything."
            )
    return problems


def run() -> list[str]:
    if not DASHBOARD_SRC.is_dir():
        return ["dashboard/src is missing — this guard has nothing to check."]
    problems: list[str] = []
    for path in sorted(DASHBOARD_SRC.rglob("*")):
        if path.suffix not in (".ts", ".tsx"):
            continue
        problems += check_file(path, path.read_text(encoding="utf-8"))
    return problems


def main() -> int:
    problems = run()
    if not problems:
        return 0
    print("Dashboard honesty check failed:\n", file=sys.stderr)
    for p in problems:
        print(f"  * {p}", file=sys.stderr)
    print(
        "\nA dashboard that fills a dead API's gap with plausible numbers is worse "
        "than one that goes blank: the operator has no way to tell.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
