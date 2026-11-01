"""Shared by the escrow tests: a buyer with a known key, and its signed consent.

Since 2026-11-01 a deposit the gateway relays carries the buyer's EIP-712
`DepositIntent` signature, and `EscrowService` recovers it before sending. Tests
of the sending path therefore sign for real rather than stub the check out —
a fixture that bypassed it would test a gateway that no longer exists.
"""
from __future__ import annotations

import time

from eth_account import Account
from eth_account.messages import encode_typed_data

#: A throwaway key used only by tests. Never funded, never used on a chain.
BUYER_KEY = "0x" + "b0" * 32
BUYER = Account.from_key(BUYER_KEY).address


def sign_intent(typed_data: dict, key: str = BUYER_KEY) -> str:
    signed = Account.sign_message(encode_typed_data(full_message=typed_data), private_key=key)
    return "0x" + bytes(signed.signature).hex()


def consent(svc, escrow_id: str, db_path: str, key: str = BUYER_KEY,
            valid_seconds: int = 900) -> int:
    """Record the buyer's signed intent on a pending escrow; returns the deadline."""
    deadline = int(time.time()) + valid_seconds
    typed = svc.deposit_intent(escrow_id, deadline, db_path=db_path)
    assert svc.record_deposit_intent(escrow_id, sign_intent(typed, key), deadline,
                                     db_path=db_path)
    return deadline
