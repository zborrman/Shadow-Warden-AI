"""
warden/ledger/money.py — integer micro-USD money value type (FT-0).

Why this exists
───────────────
Balances across the commerce stacks are floats today (REAL-typed `amount_usd`
columns, `round(x, 6)`), and float money loses cents at scale: `0.1 + 0.2 != 0.3`,
sums drift, and a take-rate computed in float and stored back as float cannot be
reconciled to zero. A money-moving product needs exact arithmetic.

`Money` is an **integer** count of micro-USD (1 USD = 1_000_000 µUSD, the same
scale `sac/preflight.py` already uses). All arithmetic stays in ints, so it is
associative, commutative, and lossless. `Decimal` is permitted *only* at the
boundary — `from_usd()` in, `to_usd()` out — and `float` is rejected outright so
it can never silently enter a money path.

Conservation
────────────
The ledger's core invariant is that value is neither created nor destroyed.
`split_fee()` is built for that: `fee + remainder == total` **exactly**, whatever
the rounding, because the remainder is defined as `total - fee`, not rounded
independently.
"""
from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal

MICROS_PER_USD = 1_000_000
_USD_QUANTUM = Decimal("0.000001")  # 1 µUSD, the finest representable unit

# What `from_usd` / `mul_rate` accept — deliberately NOT float.
Numeric = int | str | Decimal


def _reject_float(value: object, where: str) -> None:
    if isinstance(value, float):
        raise TypeError(
            f"Money.{where}: float is forbidden on money paths (got {value!r}). "
            "Pass an int, a decimal string, or a Decimal."
        )


class Money:
    """An exact amount of money, stored as integer micro-USD.

    Immutable. Construct via :meth:`from_usd` (Decimal/str/int at the boundary)
    or :meth:`from_micros`. Never constructed from ``float``.
    """

    __slots__ = ("_micros",)

    def __init__(self, micros: int) -> None:
        if isinstance(micros, bool) or not isinstance(micros, int):
            raise TypeError(f"Money(micros) requires int, got {type(micros).__name__}")
        self._micros = micros

    # ── Constructors ────────────────────────────────────────────────────────
    @classmethod
    def from_micros(cls, micros: int) -> Money:
        return cls(micros)

    @classmethod
    def from_usd(cls, value: Numeric) -> Money:
        """Round a USD amount to the nearest µUSD (banker's rounding).

        Accepts int, a decimal string (``"1.23"``), or ``Decimal``. Rejects
        ``float`` — decimal strings are the safe way to write a literal.
        """
        _reject_float(value, "from_usd")
        d = value if isinstance(value, Decimal) else Decimal(value)
        micros = int((d * MICROS_PER_USD).to_integral_value(rounding=ROUND_HALF_EVEN))
        return cls(micros)

    @classmethod
    def zero(cls) -> Money:
        return cls(0)

    # ── Boundary accessors ──────────────────────────────────────────────────
    @property
    def micros(self) -> int:
        return self._micros

    def to_usd(self) -> Decimal:
        """Exact USD value as a 6-dp Decimal (for API/display boundaries only)."""
        return (Decimal(self._micros) / MICROS_PER_USD).quantize(_USD_QUANTUM)

    # ── Arithmetic (stays integer, lossless) ────────────────────────────────
    def __add__(self, other: Money) -> Money:
        if not isinstance(other, Money):
            return NotImplemented
        return Money(self._micros + other._micros)

    def __sub__(self, other: Money) -> Money:
        if not isinstance(other, Money):
            return NotImplemented
        return Money(self._micros - other._micros)

    def __neg__(self) -> Money:
        return Money(-self._micros)

    def __mul__(self, count: int) -> Money:
        """Scale by an integer count (e.g. quantity). Not by float/Decimal —
        use :meth:`mul_rate` for a fractional rate."""
        if isinstance(count, bool) or not isinstance(count, int):
            raise TypeError("Money * n requires an int count; use mul_rate() for a rate")
        return Money(self._micros * count)

    __rmul__ = __mul__

    def mul_rate(self, rate: Numeric) -> Money:
        """Multiply by a fractional rate (e.g. ``Decimal('0.015')`` take-rate),
        rounding the result to the nearest µUSD. Float is rejected."""
        _reject_float(rate, "mul_rate")
        r = rate if isinstance(rate, Decimal) else Decimal(rate)
        micros = int((Decimal(self._micros) * r).to_integral_value(rounding=ROUND_HALF_EVEN))
        return Money(micros)

    def split_fee(self, rate: Numeric) -> tuple[Money, Money]:
        """Split into ``(fee, remainder)`` at *rate*, conserving the total.

        ``fee + remainder == self`` holds exactly: the fee is rounded, the
        remainder absorbs the rounding residue. This is the ledger-safe way to
        take a platform fee."""
        fee = self.mul_rate(rate)
        return fee, self - fee

    # ── Comparisons ─────────────────────────────────────────────────────────
    def __eq__(self, other: object) -> bool:
        return isinstance(other, Money) and other._micros == self._micros

    def __ne__(self, other: object) -> bool:
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    def __lt__(self, other: Money) -> bool:
        if not isinstance(other, Money):
            return NotImplemented
        return self._micros < other._micros

    def __le__(self, other: Money) -> bool:
        if not isinstance(other, Money):
            return NotImplemented
        return self._micros <= other._micros

    def __gt__(self, other: Money) -> bool:
        if not isinstance(other, Money):
            return NotImplemented
        return self._micros > other._micros

    def __ge__(self, other: Money) -> bool:
        if not isinstance(other, Money):
            return NotImplemented
        return self._micros >= other._micros

    def __hash__(self) -> int:
        return hash(self._micros)

    # ── Predicates ──────────────────────────────────────────────────────────
    def is_zero(self) -> bool:
        return self._micros == 0

    def is_negative(self) -> bool:
        return self._micros < 0

    def is_positive(self) -> bool:
        return self._micros > 0

    def __bool__(self) -> bool:
        return self._micros != 0

    # ── Representation ──────────────────────────────────────────────────────
    def __repr__(self) -> str:
        return f"Money({self._micros})"  # exact, unambiguous

    def __str__(self) -> str:
        return f"${self.to_usd()}"
