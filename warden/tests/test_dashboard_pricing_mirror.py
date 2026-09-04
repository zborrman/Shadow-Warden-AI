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

from warden.billing.pricing import ANNUAL_DISCOUNT, TIER_PRICE_USD_MONTH

_ROOT = Path(__file__).resolve().parents[2]
_TS = _ROOT / "dashboard" / "src" / "lib" / "pricing.ts"

#: `trial` has no card in any dashboard surface; it is an internal state, not a
#: plan someone is shown a price for. Every other tier must appear on both sides.
NOT_SHOWN_IN_DASHBOARD = frozenset({"trial"})


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


def test_no_dashboard_page_types_a_price_of_its_own() -> None:
    """The mirror only helps if pages read it.

    A hardcoded `$69/mo` in a page is exactly what this replaced, and it does
    not fail the comparison above — it simply sits beside it, disagreeing.
    """
    src_dir = _ROOT / "dashboard" / "src"
    offenders: list[str] = []
    known_prices = {f"{v:g}" for v in TIER_PRICE_USD_MONTH.values() if v}

    for path in sorted(src_dir.rglob("*.tsx")):
        if path.name == "pricing.ts":
            continue
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if "pricing" in line.lower() or line.lstrip().startswith(("//", "*", "/*")):
                continue
            for m in re.finditer(r"\$(\d+(?:\.\d+)?)\s*/\s*mo\b", line):
                if m.group(1) not in known_prices:
                    continue
                offenders.append(
                    f"{path.relative_to(_ROOT).as_posix()}:{n}: types "
                    f"${m.group(1)}/mo directly"
                )

    assert not offenders, (
        "these lines quote a plan price without going through "
        "dashboard/src/lib/pricing.ts, so they drift silently:\n  "
        + "\n  ".join(offenders)
    )
