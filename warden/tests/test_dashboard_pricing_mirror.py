"""warden/tests/test_dashboard_pricing_mirror.py — SW-8 follow-up.

`dashboard/src/lib/pricing.ts` duplicates `warden/billing/pricing.py`, because
TypeScript cannot import Python. A duplicate with nothing holding it to its
source is how this repo ended up with several price lists that disagreed
(FM-7): the ROI page divided savings by $69 to produce an "ROI Multiple" while
billing charged $99.99, inflating every multiple on the page by about 45%.

So the duplication is allowed and the drift is not. This test reads both files
and fails when they diverge — including when a tier is added on one side only,
which is the quieter half of the same problem.
"""
from __future__ import annotations

import re
from pathlib import Path

from warden.billing.pricing import (
    ANNUAL_DISCOUNT,
    TIER_PRICE_USD_MONTH,
    annual_price_usd,
)
from warden.hooks.dashboard_honesty import strip_comments

_ROOT = Path(__file__).resolve().parents[2]
_TS = _ROOT / "dashboard" / "src" / "lib" / "pricing.ts"

#: `trial` has no card in any dashboard surface; it is an internal state, not a
#: plan someone is shown a price for. Every other tier must appear on both sides.
NOT_SHOWN_IN_DASHBOARD = frozenset({"trial"})

#: A rendered price, in the spellings TSX actually produces. `${99.99}` is not a
#: template literal here — in JSX it is the text `$` followed by the expression
#: `{99.99}`, and the browser paints `$99.99`. Matching only `$99.99` let that
#: one through, which is the same failure as every other single-spelling check
#: in this PR.
_PRICE_LITERAL = re.compile(r"\$\s*\{?\s*(\d[\d,]*(?:\.\d+)?)\s*\}?")


def _parse_ts_prices(src: str) -> dict[str, float]:
    block = re.search(r"TIER_MONTHLY_USD\s*=\s*\{(.*?)\}", src, re.S)
    assert block, "TIER_MONTHLY_USD is gone from dashboard/src/lib/pricing.ts"
    return {
        m.group(1): float(m.group(2))
        for m in re.finditer(r"(\w+)\s*:\s*([0-9]+(?:\.[0-9]+)?)", block.group(1))
    }


def test_the_dashboard_quotes_the_price_billing_charges() -> None:
    assert _TS.exists(), (
        f"{_TS} is gone. The dashboard then has no shared price source and each "
        "page goes back to typing its own number, which is how $69 and $99.99 "
        "came to live in the same product."
    )
    ts = _parse_ts_prices(_TS.read_text(encoding="utf-8"))
    py = {k: v for k, v in TIER_PRICE_USD_MONTH.items() if k not in NOT_SHOWN_IN_DASHBOARD}

    assert ts == py, (
        "dashboard/src/lib/pricing.ts and warden/billing/pricing.py disagree "
        f"about list prices.\n  dashboard: {ts}\n  billing:   {py}\n"
        "warden/billing/pricing.py is canonical — it is what the customer is "
        "actually charged. Update the mirror, not the source."
    )


def test_the_annual_discount_is_not_typed_twice_differently() -> None:
    """Annual prices are derived on both sides; the rate has to match."""
    src = _TS.read_text(encoding="utf-8")
    m = re.search(r"ANNUAL_DISCOUNT\s*=\s*([0-9.]+)", src)
    assert m, "ANNUAL_DISCOUNT is gone from the dashboard mirror"
    assert float(m.group(1)) == ANNUAL_DISCOUNT, (
        f"the dashboard applies a {m.group(1)} annual discount, billing applies "
        f"{ANNUAL_DISCOUNT}. An annual price quoted at a discount nobody grants "
        "is a promise the invoice will not keep."
    )


def _canonical_amounts() -> set[float]:
    """Every list price a page could type: monthly, and derived annual.

    Annual is derived here for the same reason it is derived in
    `warden/billing/pricing.py` — a typed annual figure is how
    pricing-calculator.tsx came to show Enterprise at 2541 when 15% off its own
    monthly price is 2539.80.
    """
    amounts: set[float] = set()
    for monthly in TIER_PRICE_USD_MONTH.values():
        amounts.add(round(monthly, 2))
        if monthly:
            amounts.add(round(monthly * 12 * (1 - ANNUAL_DISCOUNT), 2))
    return amounts


def test_no_dashboard_page_types_a_price_of_its_own() -> None:
    """The mirror only helps if pages read it.

    A hardcoded price does not fail the comparison above — it sits beside it,
    disagreeing. This caught a leftover `$99.99/mo` in roi/page.tsx that the
    numeric comparison was blind to.

    The first version had three bypasses, all of them the same mistake the rest
    of this PR is about — a check that matches one spelling:

      * it skipped any line containing the substring "pricing", so
        `<p data-testid="pricing">$99.99/mo</p>` passed. That is the same loose
        substring match that let a commented-out variable satisfy the SMB
        perimeter guard.
      * it required a `/mo` suffix, so an annual literal was invisible.
      * it dropped zero-priced tiers, so a typed `$0/mo` on a paid plan passed.

    And two more after that, in both directions at once:

      * `${99.99}` in JSX renders `$99.99` and did not match, so the bypass
        survived a round of closing bypasses;
      * comments were skipped by line prefix, which misses a block-comment
        continuation line and a trailing comment — so a price written in prose
        could fail the test. Comment handling now goes through the honesty
        guard's own traversal, which already knows a `//` inside a string is
        not a comment.
    """
    src_dir = _ROOT / "dashboard" / "src"
    canonical = _canonical_amounts()
    offenders: list[str] = []

    for path in sorted(src_dir.rglob("*")):
        if path.suffix not in (".ts", ".tsx") or path == _TS:
            continue
        code = strip_comments(path.read_text(encoding="utf-8"))
        for n, line in enumerate(code.splitlines(), 1):
            for m in _PRICE_LITERAL.finditer(line):
                try:
                    amount = round(float(m.group(1).replace(",", "")), 2)
                except ValueError:
                    continue
                if amount in canonical:
                    offenders.append(
                        f"{path.relative_to(_ROOT).as_posix()}:{n}: types "
                        f"${m.group(1)}, a canonical list price"
                    )

    assert not offenders, (
        "these lines quote a plan price without going through "
        "dashboard/src/lib/pricing.ts, so they drift silently:\n  "
        + "\n  ".join(offenders)
    )


def test_the_price_scanner_reads_what_the_browser_renders() -> None:
    """Regression cases for every bypass this scanner has had.

    Kept as explicit inputs rather than trusting the tree to contain them: the
    tree is clean by construction after each fix, so a bypass that reopens
    would go unnoticed until someone used it.
    """
    canonical = _canonical_amounts()

    def flags(line: str) -> bool:
        code = strip_comments(line)
        return any(
            round(float(m.group(1).replace(",", "")), 2) in canonical
            for m in _PRICE_LITERAL.finditer(code)
        )

    for rendered in (
        '<p>$99.99/mo</p>',
        '<p data-testid="pricing">$99.99/mo</p>',
        '<p>${99.99}/mo</p>',
        '<span>$1,019.90/year</span>',
        '<span>$0/mo</span>',
        'const label = "$39.99 per month";',
    ):
        assert flags(rendered), (
            f"the scanner missed {rendered!r}, which renders a canonical list "
            "price the page did not read from the mirror."
        )

    for benign in (
        "// Pro is $99.99/mo — see warden/billing/pricing.py",
        "/* $99.99 */",
        "const x = 1;  // was $99.99/mo before the mirror",
        "const price = formatMonthly(\"pro\");",
        "const budget = 100;",
    ):
        assert not flags(benign), (
            f"the scanner flagged {benign!r}. A price named in a comment is "
            "documentation, not a duplicate — and a test that fails on prose "
            "gets deleted."
        )


def test_the_mirror_copies_the_contract_not_only_the_numbers() -> None:
    """`annualPriceUsd` must return null for a tier with no annual plan.

    `warden/billing/pricing.py::annual_price_usd` returns None for a zero-priced
    tier. The mirror returned 0, which a caller renders as a "$0/year" plan that
    cannot be bought. Matching the numbers and not the behaviour is half a
    mirror, and the half that is missing is the one nobody notices.
    """
    src = _TS.read_text(encoding="utf-8")
    assert "number | null" in src, (
        "annualPriceUsd no longer admits null, so a free tier reports a $0 "
        "annual plan instead of no annual plan."
    )
    assert re.search(r"if \(!monthly\)\s*return null", src), (
        "the zero-price guard is gone from annualPriceUsd"
    )
    assert annual_price_usd("starter") is None, (
        "the Python side changed; re-check what the mirror should now return"
    )
