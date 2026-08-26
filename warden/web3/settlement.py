"""
warden/web3/settlement.py
──────────────────────────
The payload half of on-chain settlement — Phase 1 of `docs/onchain-settlement-design.md`.

`call_escrow()` in `smart_contract.py` is the transport: it builds, signs, sends
and reads the receipt, and fails closed. It has been finished since 2026-08-24.
What was never written is the payload. `EscrowService.fund_escrow()` called
``deposit`` with ``{}`` while the contract wants
``(bytes32, address, address, address, uint256, uint64)``, and the escrow record
held agent DIDs and a USD float — nothing an argument could be built from.

This module supplies the three things that gap needs, and **nothing that sends**:

  * :func:`trade_id_for`     — the deterministic key a retry must reproduce
  * :func:`to_minor_units`   — USD → integer token units, refusing to round to 0
  * :func:`settlement_preflight` — the seven checks that run before a transaction
    is built, so a refusal names its cause instead of arriving as ``REVERTED``

Deliberately inert where settlement is not configured. `settlement_capability()`
returns ``can_settle: False`` for every deployment today, and every entry point
here returns a refusal rather than raising — a settlement path should decline to
send, not crash the request that asked it to.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from typing import Any

from warden.web3.chains import DEFAULT_CHAIN, get_chain, verify_usdc_contract
from warden.web3.smart_contract import _contract_address, settlement_capability

log = logging.getLogger("warden.web3.settlement")

#: Derived with `keccak(text=sig)[:4]`, not copied from documentation — the same
#: reason `chains.py` verifies its own USDC addresses against the chain.
_SEL_ALLOWANCE = "0xdd62ed3e"   # allowance(address,address)
_SEL_BALANCE_OF = "0x70a08231"  # balanceOf(address)

#: Namespaced so a trade id can never collide with a hash of something else that
#: happens to share an escrow's identifier.
_TRADE_ID_PREFIX = "shadow-warden:escrow:"


class SettlementRefused(RuntimeError):  # noqa: N818 — reads as a verdict, not a crash
    """Raised when a conversion cannot produce a value it is safe to settle."""


# ── deterministic trade id ────────────────────────────────────────────────────

def trade_id_for(escrow_id: str) -> str:
    """The contract's `bytes32 tradeId` for an escrow, as a 0x-prefixed string.

    Deterministic, so a retry after a timeout addresses the **same** trade. That
    matters more than it looks: `Escrow.sol` reverts `TradeExists()` on a second
    `deposit`, and the caller must read that revert as *success*. A random id
    would instead open a second trade for the same escrow and fund it twice.
    """
    if not escrow_id:
        raise SettlementRefused("cannot derive a trade id from an empty escrow id")
    try:
        from eth_utils import keccak  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - requires web3 absent
        raise SettlementRefused(f"keccak unavailable: {exc}") from exc
    return "0x" + keccak(text=_TRADE_ID_PREFIX + escrow_id).hex()


# ── amount conversion ─────────────────────────────────────────────────────────

def to_minor_units(amount_usd: float | str | Decimal, decimals: int) -> int:
    """Convert a USD figure to integer token minor units.

    `Decimal(str(x))`, never `Decimal(x)`: the latter inherits the binary float's
    representation error and reintroduces precisely what Decimal is here to
    prevent. `amount_usd` is a SQLite REAL, so it arrives as a float.

    Refuses to return 0. Settling a trade for zero tokens and recording it as
    released is the $0.00 clearing defect one layer down, and it would satisfy
    every test that only asserts on state transitions.
    """
    if decimals < 0 or decimals > 36:
        raise SettlementRefused(f"implausible token decimals: {decimals}")
    try:
        scaled = Decimal(str(amount_usd)) * (Decimal(10) ** decimals)
        minor = int(scaled.quantize(Decimal("1"), rounding=ROUND_HALF_UP))
    except (InvalidOperation, ValueError, TypeError) as exc:
        raise SettlementRefused(f"{amount_usd!r} is not a settleable amount") from exc

    if minor <= 0:
        raise SettlementRefused(
            f"${amount_usd} rounds to {minor} units at {decimals} decimals; refusing"
        )
    return minor


# ── preflight ─────────────────────────────────────────────────────────────────

@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class Preflight:
    """The verdict, and every check that produced it.

    `checks` is kept whole rather than short-circuited into a single reason so an
    operator sees which of the seven passed. "Cannot settle" with no cause is how
    someone ends up believing it was a network blip.
    """
    ok: bool
    #: Whether this deployment is configured to settle at all, as distinct from
    #: configured but not ready. The caller needs both: unconfigured means
    #: simulate and carry on, not-ready means refuse and stay put.
    configured: bool = False
    reason: str = ""
    detail: str = ""
    trade_id: str = ""
    amount_minor: int = 0
    token_address: str = ""
    token_decimals: int = 0
    checks: list[Check] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "configured": self.configured,
            "reason": self.reason,
            "detail": self.detail,
            "trade_id": self.trade_id,
            "amount_minor": str(self.amount_minor),
            "token_address": self.token_address,
            "token_decimals": self.token_decimals,
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
        }


def _erc20_uint(w3: Any, token: str, selector: str, *addresses: str) -> int:
    """One ERC-20 view call returning a uint256, via eth_call and no ABI file."""
    data = selector + "".join(a.lower().replace("0x", "").rjust(64, "0") for a in addresses)
    return int.from_bytes(w3.eth.call({"to": token, "data": data}), "big")


def settlement_preflight(
    *,
    escrow_id: str,
    amount_usd: float,
    buyer_address: str,
    seller_address: str,
    chain: str = DEFAULT_CHAIN,
    w3: Any = None,
) -> Preflight:
    """Decide whether this escrow can be settled, before anything is built.

    Never raises and never sends. On a failed check the caller leaves the escrow
    in its current state with `reason` recorded — it does not advance.

    The two allowance/balance checks are the reason this exists at all rather
    than trusting the revert: `deposit` fails with `TransferFailed()` for both,
    they are the likeliest first-trade failures, and the receipt cannot tell them
    apart.
    """
    checks: list[Check] = []

    def _fail(reason: str, detail: str = "", configured: bool = True) -> Preflight:
        checks.append(Check(reason, False, detail))
        return Preflight(ok=False, configured=configured, reason=reason,
                         detail=detail, checks=checks)

    # 1 — is settlement configured for this chain at all. Local: environment and
    #     a packaged file, no network, so an unconfigured deployment pays nothing
    #     for asking.
    cap = settlement_capability(chain)
    if not cap["can_settle"]:
        return _fail(cap["reason"], cap["detail"], configured=False)
    checks.append(Check("settlement_configured", True, chain))

    # 2 — addresses well-formed. A malformed address is a configuration error,
    #     not a chain error, and must not be discovered by a failed transaction.
    try:
        from web3 import Web3  # noqa: PLC0415
    except Exception as exc:  # pragma: no cover - capability check covers this
        return _fail("web3_not_installed", str(exc))

    for label, addr in (("buyer", buyer_address), ("seller", seller_address)):
        if not addr:
            return _fail(f"no_{label}_address",
                         f"the {label} has no payout address recorded")
        if not Web3.is_address(addr):
            return _fail(f"bad_{label}_address", f"{addr!r} is not an address")
    buyer = Web3.to_checksum_address(buyer_address)
    seller = Web3.to_checksum_address(seller_address)
    checks.append(Check("addresses_valid", True, f"{buyer[:10]}… → {seller[:10]}…"))

    # 3 — a token to settle in. `sepolia` has none, which is why the chain P1a
    #     deployed on cannot settle USDC at all.
    token_cfg = get_chain(chain).get("usdc_address") or ""
    if not token_cfg:
        return _fail("no_token", f"no USDC address is configured for {chain!r}")
    checks.append(Check("token_configured", True, token_cfg))

    w3 = w3 or Web3(Web3.HTTPProvider(get_chain(chain)["rpc_url"]))

    # 4 — the token is the token it claims to be
    verdict = verify_usdc_contract(chain, w3)
    if not verdict.get("ok"):
        return _fail("token_unverified", str(verdict.get("reason", "")))
    decimals = int(verdict.get("decimals", 6))
    token = Web3.to_checksum_address(token_cfg)
    checks.append(Check("token_verified", True, f"USDC/{decimals}"))

    # 5 — an amount that is worth moving
    try:
        minor = to_minor_units(amount_usd, decimals)
        trade_id = trade_id_for(escrow_id)
    except SettlementRefused as exc:
        return _fail("unsettleable_amount", str(exc))
    checks.append(Check("amount_convertible", True, f"{minor} units"))

    escrow_contract = _contract_address(chain) or ""

    # 6 + 7 — the two that produce an indistinguishable TransferFailed()
    try:
        allowance = _erc20_uint(w3, token, _SEL_ALLOWANCE, buyer, escrow_contract)
        balance = _erc20_uint(w3, token, _SEL_BALANCE_OF, buyer)
        gas_balance = w3.eth.get_balance(
            Web3.to_checksum_address(_signer_address(w3))
        )
    except Exception as exc:  # noqa: BLE001 — a check reports, it does not raise
        return _fail("chain_unreadable", f"{type(exc).__name__}: {exc}")

    if allowance < minor:
        return _fail(
            "insufficient_allowance",
            f"buyer has approved {allowance} units to the escrow, needs {minor}",
        )
    checks.append(Check("allowance_sufficient", True, str(allowance)))

    if balance < minor:
        return _fail(
            "insufficient_balance",
            f"buyer holds {balance} units, needs {minor}",
        )
    checks.append(Check("balance_sufficient", True, str(balance)))

    if gas_balance <= 0:
        # Out of gas and a rejected transaction look identical in a receipt.
        return _fail("no_gas", "the signing key holds no native currency")
    checks.append(Check("gas_available", True, str(gas_balance)))

    return Preflight(
        ok=True,
        configured=True,
        trade_id=trade_id,
        amount_minor=minor,
        token_address=token,
        token_decimals=decimals,
        checks=checks,
    )


def _signer_address(w3: Any) -> str:
    """The address that will pay gas. Read from the key, never from config."""
    return w3.eth.account.from_key(os.getenv("WEB3_SIGNER_KEY", "").strip()).address


def deposit_params(pre: Preflight, buyer: str, seller: str, window_seconds: int) -> dict:
    """The arguments `deposit` has always wanted, keyed by their ABI names.

    Named parameters rather than positional because `call_escrow` passes them as
    ``**params``, and because the test that guards this compares these keys
    against the ABI's declared inputs — the check that ``deposit({})`` fails.
    """
    if not pre.ok:
        raise SettlementRefused(f"preflight did not pass: {pre.reason}")
    return {
        "tradeId": bytes.fromhex(pre.trade_id[2:]),
        "buyer": buyer,
        "seller": seller,
        "token": pre.token_address,
        "amount": pre.amount_minor,
        "deliveryWindowSeconds": int(window_seconds),
    }
