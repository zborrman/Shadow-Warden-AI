"""
warden/ledger/operations.py — canonical money flows on the ledger (FT-2).

The named, idempotent operations that higher layers call instead of hand-writing
postings. Each is a thin, balanced wrapper over `journal.post()` (or the two-phase
`holds` API) implementing exactly one flow from docs/fintech-architecture.md §3, so
every money movement in the product routes through one audited vocabulary.

This is the **target API** for FT-2: the live balance writers (Flex Credits,
wallet funding, SAC preflight holds, marketplace clearing) re-point here in a
follow-on slice. Purely additive — nothing is rewired yet.

All amounts are integer µUSD (`Money`); every call requires an `idempotency_key`
so a retried webhook or double-submitted request moves value at most once
(the journal enforces UNIQUE + replay-no-op). Convention: an account's posting is
the signed delta to its balance; `tenant:*` / `promo:*` credit balances go up as
positive, funded by a negative posting to the processor receivable or the promo
expense account.
"""
from __future__ import annotations

from decimal import Decimal

from warden.ledger import accounts, journal
from warden.ledger.holds import capture, reserve, void  # re-export: one import surface
from warden.ledger.journal import Posting, Transaction
from warden.ledger.money import Money

__all__ = [
    "topup", "grant_trial", "grant_bonus", "grant_credits", "purchase",
    "reserve", "capture", "void",
]


def _require_positive(amount: Money, what: str) -> None:
    if not amount.is_positive():
        raise journal.LedgerError(f"{what} must be positive, got {amount.micros} µUSD")


def topup(
    tenant_id: str, amount: Money, *, idempotency_key: str, processor: str = "stripe",
    db_path: str | None = None,
) -> Transaction:
    """Tenant deposits *amount* → their cash balance rises, offset by the processor
    receivable (recon anchor)."""
    _require_positive(amount, "topup amount")
    return journal.post(
        idempotency_key, "topup",
        [Posting(accounts.tenant_cash(tenant_id), amount),
         Posting(accounts.processor_clearing(processor), -amount)],
        db_path=db_path,
    )


def grant_credits(
    tenant_id: str, amount: Money, *, idempotency_key: str, processor: str = "stripe",
    db_path: str | None = None,
) -> Transaction:
    """Tenant buys prepaid Flex Credits (carried in µUSD; 1 credit = 1000 µUSD)."""
    _require_positive(amount, "credit amount")
    return journal.post(
        idempotency_key, "grant_credits",
        [Posting(accounts.tenant_credits(tenant_id), amount),
         Posting(accounts.processor_clearing(processor), -amount)],
        db_path=db_path,
    )


def grant_trial(
    tenant_id: str, amount: Money, *, idempotency_key: str, db_path: str | None = None,
) -> Transaction:
    """Welcome-trial grant — spendable free balance funded by platform promo expense."""
    _require_positive(amount, "trial amount")
    return journal.post(
        idempotency_key, "grant_trial",
        [Posting(accounts.promo_trial(tenant_id), amount),
         Posting(accounts.platform_promo_expense(), -amount)],
        db_path=db_path,
    )


def grant_bonus(
    tenant_id: str, amount: Money, *, idempotency_key: str, db_path: str | None = None,
) -> Transaction:
    """Referral kickback — bonus balance funded by platform promo expense (NF-2)."""
    _require_positive(amount, "bonus amount")
    return journal.post(
        idempotency_key, "grant_bonus",
        [Posting(accounts.promo_bonus(tenant_id), amount),
         Posting(accounts.platform_promo_expense(), -amount)],
        db_path=db_path,
    )


def purchase(
    buyer_tenant: str, seller_tenant: str, gross: Money, fee_rate: Decimal, *,
    idempotency_key: str, db_path: str | None = None,
) -> Transaction:
    """Marketplace clearing: buyer pays *gross*, platform takes a *fee_rate* cut,
    seller nets the remainder. Fee split conserves exactly (Money.split_fee)."""
    _require_positive(gross, "purchase gross")
    if buyer_tenant == seller_tenant:
        raise journal.LedgerError("buyer and seller must differ")
    fee, net = gross.split_fee(fee_rate)
    postings = [
        Posting(accounts.tenant_cash(buyer_tenant), -gross),
        Posting(accounts.tenant_cash(seller_tenant), net),
    ]
    if fee.is_positive():
        postings.append(Posting(accounts.platform_fees(), fee))
    else:
        # zero-fee: keep it a valid 2-posting transaction (seller gets the gross)
        postings[1] = Posting(accounts.tenant_cash(seller_tenant), gross)
    return journal.post(idempotency_key, "purchase", postings, db_path=db_path)
