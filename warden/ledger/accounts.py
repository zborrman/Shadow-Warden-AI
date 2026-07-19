"""
warden/ledger/accounts.py — chart of accounts (FT-1).

Every posting names an account with the grammar ``<namespace>:<owner>[:<leaf>]``.
The namespace is a closed set; the constructors below are the only sanctioned way
to build an account id so the string form stays canonical and greppable. The
``side`` (DEBIT/CREDIT normal) drives reporting sign conventions but does **not**
constrain postings — the journal's only hard rule is that each transaction's
signed amounts sum to zero (see `journal.py`).

Canonical accounts (from docs/fintech-architecture.md §3):

    tenant:{id}:cash          liability  — prepaid deposits owed to the tenant
    tenant:{id}:credits       liability  — Flex Credits (1 credit = 1000 µUSD)
    promo:{id}:trial          liability  — welcome-trial grant
    promo:{id}:bonus          liability  — referral kickback
    hold:{hold_id}            contra     — two-phase reservation
    escrow:{order_id}         liability  — in-flight order funds
    platform:fees             revenue    — take-rate, surcharges
    platform:promo_expense    expense    — funding source of trial/bonus grants
    processor:{name}:clearing asset      — Lemon/Stripe/USDC receivable (recon anchor)
"""
from __future__ import annotations

from enum import StrEnum

_SEP = ":"


class Namespace(StrEnum):
    TENANT = "tenant"
    PROMO = "promo"
    HOLD = "hold"
    ESCROW = "escrow"
    PLATFORM = "platform"
    PROCESSOR = "processor"


class Side(StrEnum):
    DEBIT = "debit"
    CREDIT = "credit"


# Normal side per namespace — assets/expenses are debit-normal; liabilities,
# revenue, and contra reservations are credit-normal.
_NORMAL_SIDE: dict[Namespace, Side] = {
    Namespace.TENANT: Side.CREDIT,     # liability to the tenant
    Namespace.PROMO: Side.CREDIT,      # liability (granted balance)
    Namespace.HOLD: Side.CREDIT,       # contra reservation
    Namespace.ESCROW: Side.CREDIT,     # liability (funds in flight)
    Namespace.PLATFORM: Side.CREDIT,   # revenue (fees); promo_expense flips at report time
    Namespace.PROCESSOR: Side.DEBIT,   # asset (receivable)
}


class AccountError(ValueError):
    """Raised for a malformed or unknown account id."""


def _clean(part: str, what: str) -> str:
    p = (part or "").strip()
    if not p:
        raise AccountError(f"account {what} must be non-empty")
    if _SEP in p:
        raise AccountError(f"account {what} may not contain {_SEP!r}: {part!r}")
    return p


def make(namespace: Namespace | str, owner: str, leaf: str | None = None) -> str:
    """Build a canonical account id, validating each part."""
    ns = namespace if isinstance(namespace, Namespace) else Namespace(namespace)
    parts = [ns.value, _clean(owner, "owner")]
    if leaf is not None:
        parts.append(_clean(leaf, "leaf"))
    return _SEP.join(parts)


def parse(account_id: str) -> tuple[Namespace, str, str | None]:
    """Split an account id into (namespace, owner, leaf). Raises on unknown ns."""
    parts = (account_id or "").split(_SEP)
    if len(parts) < 2 or len(parts) > 3:
        raise AccountError(f"account id must be 'ns:owner[:leaf]': {account_id!r}")
    try:
        ns = Namespace(parts[0])
    except ValueError as exc:
        raise AccountError(f"unknown account namespace: {parts[0]!r}") from exc
    owner = _clean(parts[1], "owner")
    leaf = _clean(parts[2], "leaf") if len(parts) == 3 else None
    return ns, owner, leaf


def validate(account_id: str) -> str:
    """Return *account_id* unchanged if well-formed, else raise AccountError."""
    parse(account_id)
    return account_id


def normal_side(account_id: str) -> Side:
    ns, _, _ = parse(account_id)
    return _NORMAL_SIDE[ns]


# ── Canonical constructors ──────────────────────────────────────────────────
def tenant_cash(tenant_id: str) -> str:
    return make(Namespace.TENANT, tenant_id, "cash")


def tenant_credits(tenant_id: str) -> str:
    return make(Namespace.TENANT, tenant_id, "credits")


def promo_trial(tenant_id: str) -> str:
    return make(Namespace.PROMO, tenant_id, "trial")


def promo_bonus(tenant_id: str) -> str:
    return make(Namespace.PROMO, tenant_id, "bonus")


def hold(hold_id: str) -> str:
    return make(Namespace.HOLD, hold_id)


def escrow(order_id: str) -> str:
    return make(Namespace.ESCROW, order_id)


def platform_fees() -> str:
    return make(Namespace.PLATFORM, "fees")


def platform_promo_expense() -> str:
    return make(Namespace.PLATFORM, "promo_expense")


def processor_clearing(name: str) -> str:
    return make(Namespace.PROCESSOR, name, "clearing")
