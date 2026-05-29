"""
warden/web3/chain_connector.py
Abstraction layer for Ethereum-compatible blockchains.
Supports live RPC (Sepolia/Polygon) and local eth_tester simulation.
"""
from __future__ import annotations

import logging
import os
from typing import Any

log = logging.getLogger("warden.blockchain.chain")

_RPC_URL  = os.getenv("WEB3_RPC_URL", "")          # e.g. https://sepolia.infura.io/v3/KEY
_CHAIN_ID = int(os.getenv("WEB3_CHAIN_ID", "11155111"))  # Sepolia default
_USE_TESTER = not bool(_RPC_URL)                    # in-process simulator when no RPC


def _build_web3():
    try:
        from web3 import Web3
        if _USE_TESTER:
            from eth_tester import EthereumTester, PyEVMBackend
            from web3.providers.eth_tester import EthereumTesterProvider
            tester = EthereumTester(PyEVMBackend())
            return Web3(EthereumTesterProvider(tester)), tester
        return Web3(Web3.HTTPProvider(_RPC_URL)), None
    except ImportError:
        log.warning("web3/eth_tester not installed — blockchain features disabled")
        return None, None


_w3, _tester = _build_web3()


class ChainConnector:
    """
    Thin wrapper around web3.py.  All methods return None / empty dict
    on ImportError so the rest of the service fails-open.
    """

    @property
    def w3(self):
        return _w3

    @property
    def available(self) -> bool:
        return _w3 is not None

    def get_block_number(self) -> int | None:
        if not _w3:
            return None
        try:
            return _w3.eth.block_number
        except Exception as exc:
            log.debug("get_block_number: %s", exc)
            return None

    def get_accounts(self) -> list[str]:
        if not _w3:
            return []
        try:
            return list(_w3.eth.accounts)
        except Exception:
            return []

    def deploy_contract(self, abi: list, bytecode: str, deployer: str, *args) -> str | None:
        if not _w3:
            return None
        try:
            contract = _w3.eth.contract(abi=abi, bytecode=bytecode)
            tx_hash = contract.constructor(*args).transact({"from": deployer})
            receipt = _w3.eth.wait_for_transaction_receipt(tx_hash)
            return receipt.contractAddress
        except Exception as exc:
            log.error("deploy_contract failed: %s", exc)
            return None

    def call_function(
        self,
        address: str,
        abi: list,
        fn_name: str,
        *args,
        sender: str | None = None,
    ) -> Any:
        if not _w3:
            return None
        try:
            contract = _w3.eth.contract(address=address, abi=abi)
            fn = getattr(contract.functions, fn_name)(*args)
            if sender:
                tx_hash = fn.transact({"from": sender})
                return _w3.eth.wait_for_transaction_receipt(tx_hash)
            return fn.call()
        except Exception as exc:
            log.error("call_function %s: %s", fn_name, exc)
            return None


_connector = ChainConnector()


def get_connector() -> ChainConnector:
    return _connector
