"""
warden/web3/mandate_contract.py
On-chain mandate interface via pre-compiled ABI.
Falls back to in-process simulation (eth_tester) when no RPC configured.
"""
from __future__ import annotations

import hashlib
import logging
import os
from typing import Any

log = logging.getLogger("warden.blockchain.mandate")

# Minimal ABI for compiled Mandate.sol
MANDATE_ABI = [
    {
        "inputs": [
            {"name": "mandateId",  "type": "bytes32"},
            {"name": "tenantId",   "type": "string"},
            {"name": "maxAmount",  "type": "uint256"},
            {"name": "validUntil", "type": "uint256"},
            {"name": "merchants",  "type": "string[]"},
            {"name": "ipfsHash",   "type": "string"},
        ],
        "name": "createMandate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "mandateId", "type": "bytes32"},
            {"name": "amount",    "type": "uint256"},
            {"name": "merchant",  "type": "string"},
        ],
        "name": "executePayment",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "mandateId", "type": "bytes32"}],
        "name": "revokeMandate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "mandateId", "type": "bytes32"}],
        "name": "getMandate",
        "outputs": [
            {
                "components": [
                    {"name": "tenantId",    "type": "string"},
                    {"name": "maxAmount",   "type": "uint256"},
                    {"name": "spentAmount", "type": "uint256"},
                    {"name": "validUntil",  "type": "uint256"},
                    {"name": "owner",       "type": "address"},
                    {"name": "active",      "type": "bool"},
                    {"name": "ipfsHash",    "type": "string"},
                ],
                "type": "tuple",
            },
            {"type": "string[]"},
        ],
        "stateMutability": "view",
        "type": "function",
    },
]

# Bytecode for eth_tester simulation (minimal stub — real deployment uses solc)
_STUB_BYTECODE = "0x" + "60" * 32  # placeholder for test environment

_CONTRACT_ADDRESS = os.getenv("WEB3_MANDATE_CONTRACT", "")


class MandateContract:
    """
    Wraps the Mandate.sol contract. Uses a persistent address from
    WEB3_MANDATE_CONTRACT env, or auto-deploys to eth_tester on first use.
    """

    def __init__(self) -> None:
        from warden.blockchain.chain_connector import get_connector
        self._chain = get_connector()
        self._address: str | None = _CONTRACT_ADDRESS or None
        self._ensure_deployed()

    def _ensure_deployed(self) -> None:
        if self._address or not self._chain.available:
            return
        accounts = self._chain.get_accounts()
        if not accounts:
            return
        addr = self._chain.deploy_contract(
            MANDATE_ABI, _STUB_BYTECODE, accounts[0]
        )
        if addr:
            self._address = addr
            log.info("Mandate contract deployed at %s (eth_tester)", addr)

    @staticmethod
    def _mandate_id(mandate_uuid: str) -> bytes:
        return hashlib.sha256(mandate_uuid.encode()).digest()

    def create(
        self,
        mandate_uuid: str,
        tenant_id: str,
        max_amount_cents: int,
        valid_until_ts: int,
        merchants: list[str],
        ipfs_hash: str = "",
    ) -> dict[str, Any]:
        if not self._address or not self._chain.available:
            return {"success": False, "reason": "blockchain_unavailable"}
        accounts = self._chain.get_accounts()
        if not accounts:
            return {"success": False, "reason": "no_accounts"}
        receipt = self._chain.call_function(
            self._address, MANDATE_ABI, "createMandate",
            self._mandate_id(mandate_uuid),
            tenant_id,
            max_amount_cents,
            valid_until_ts,
            merchants,
            ipfs_hash,
            sender=accounts[0],
        )
        return {"success": receipt is not None, "tx": str(receipt), "address": self._address}

    def execute_payment(
        self,
        mandate_uuid: str,
        amount_cents: int,
        merchant: str,
    ) -> dict[str, Any]:
        if not self._address or not self._chain.available:
            return {"success": False, "reason": "blockchain_unavailable"}
        accounts = self._chain.get_accounts()
        if not accounts:
            return {"success": False, "reason": "no_accounts"}
        receipt = self._chain.call_function(
            self._address, MANDATE_ABI, "executePayment",
            self._mandate_id(mandate_uuid),
            amount_cents,
            merchant,
            sender=accounts[0],
        )
        return {"success": receipt is not None}

    def revoke(self, mandate_uuid: str) -> dict[str, Any]:
        if not self._address or not self._chain.available:
            return {"success": False, "reason": "blockchain_unavailable"}
        accounts = self._chain.get_accounts()
        if not accounts:
            return {"success": False, "reason": "no_accounts"}
        receipt = self._chain.call_function(
            self._address, MANDATE_ABI, "revokeMandate",
            self._mandate_id(mandate_uuid),
            sender=accounts[0],
        )
        return {"success": receipt is not None}

    def get(self, mandate_uuid: str) -> dict[str, Any]:
        if not self._address or not self._chain.available:
            return {}
        result = self._chain.call_function(
            self._address, MANDATE_ABI, "getMandate",
            self._mandate_id(mandate_uuid),
        )
        if not result:
            return {}
        record, merchants = result
        return {
            "tenant_id":    record[0],
            "max_amount":   record[1],
            "spent_amount": record[2],
            "valid_until":  record[3],
            "owner":        record[4],
            "active":       record[5],
            "ipfs_hash":    record[6],
            "merchants":    list(merchants),
        }
