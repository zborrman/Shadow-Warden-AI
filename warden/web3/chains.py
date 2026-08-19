"""
warden/web3/chains.py
──────────────────────
Multi-chain configuration for Cross-chain Escrow.

Supported networks:
  sepolia           — Ethereum Sepolia testnet (default)
  polygon_amoy      — Polygon Amoy testnet
  arbitrum_sepolia  — Arbitrum Sepolia testnet
  base_sepolia      — Base Sepolia testnet  (P1a settlement target)
  base              — Base mainnet          (P1a settlement target)

**RPC URLs are resolved per call, never snapshotted at import.** The previous
version built the whole table at module import, so a URL exported after the
first import of this module was invisible for the life of the process — the
same defect the key-hygiene rule already forbids for signing keys. `get_chain()`
reads `settings` when asked.

`usdc_address` is the Circle USDC contract for each chain, and every value here
was verified on 2026-08-19 by calling `symbol()` and `decimals()` on the address
itself rather than copied from documentation:

    base     8453   symbol='USDC' decimals=6
    base_sepolia 84532  symbol='USDC' decimals=6

`verify_usdc_contract()` repeats that check at runtime. A token address is the
one constant where being wrong costs real money silently — funds go to an
address that looks plausible and nothing comes back — so it is checked against
the chain rather than trusted.
"""
from __future__ import annotations

from typing import Any

from warden.config import settings

# ERC-20 selectors. Used through eth_call so no ABI file is needed for a check
# this small: keccak("symbol()")[:4] and keccak("decimals()")[:4].
_SELECTOR_SYMBOL = "0x95d89b41"
_SELECTOR_DECIMALS = "0x313ce567"

#: Static per-chain facts. RPC URLs deliberately absent — see module docstring.
_CHAIN_FACTS: dict[str, dict[str, Any]] = {
    "sepolia": {
        "chain_id": 11155111,
        "currency_symbol": "ETH",
        "block_explorer": "https://sepolia.etherscan.io",
        "usdc_address": "",
    },
    "polygon_amoy": {
        "chain_id": 80002,
        "currency_symbol": "MATIC",
        "block_explorer": "https://www.oklink.com/amoy",
        "usdc_address": "",
    },
    "arbitrum_sepolia": {
        "chain_id": 421614,
        "currency_symbol": "ETH",
        "block_explorer": "https://sepolia.arbiscan.io",
        "usdc_address": "",
    },
    "base_sepolia": {
        "chain_id": 84532,
        "currency_symbol": "ETH",
        "block_explorer": "https://sepolia.basescan.org",
        "usdc_address": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    },
    "base": {
        "chain_id": 8453,
        "currency_symbol": "ETH",
        "block_explorer": "https://basescan.org",
        "usdc_address": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    },
}

_LABELS: dict[str, str] = {
    "sepolia": "Ethereum Sepolia",
    "polygon_amoy": "Polygon Amoy",
    "arbitrum_sepolia": "Arbitrum Sepolia",
    "base_sepolia": "Base Sepolia",
    "base": "Base",
}

#: Chains whose settlement is real value rather than test tokens. Kept explicit
#: so a caller can refuse to treat a testnet trade as proof of a working rail.
MAINNET_CHAINS: frozenset[str] = frozenset({"base"})

VALID_CHAINS: frozenset[str] = frozenset(_CHAIN_FACTS.keys())
DEFAULT_CHAIN = "sepolia"


def _rpc_url(chain: str) -> str:
    """Current RPC URL for a chain, read from settings at call time."""
    return {
        "sepolia": settings.sepolia_rpc_url or settings.web3_rpc_url,
        "polygon_amoy": settings.polygon_amoy_rpc_url,
        "arbitrum_sepolia": settings.arbitrum_sepolia_rpc_url,
        "base_sepolia": settings.base_sepolia_rpc_url,
        "base": settings.base_rpc_url,
    }.get(chain, "")


def get_chain(chain: str) -> dict:
    """Return chain config or raise ValueError for unknown chain names."""
    if chain not in _CHAIN_FACTS:
        raise ValueError(
            f"Unknown chain '{chain}'. Valid options: {sorted(VALID_CHAINS)}."
        )
    return {**_CHAIN_FACTS[chain], "rpc_url": _rpc_url(chain)}


def chain_label(chain: str) -> str:
    """Return a human-readable label for display (e.g. 'Polygon Amoy')."""
    return _LABELS.get(chain, chain)


def is_mainnet(chain: str) -> bool:
    """True when a trade on this chain moves real value."""
    return chain in MAINNET_CHAINS


def _decode_abi_string(raw: bytes) -> str:
    """Decode an ABI-encoded dynamic string returned by eth_call."""
    if len(raw) >= 96:
        length = int.from_bytes(raw[32:64], "big")
        return raw[64:64 + length].decode("utf-8", "replace")
    return raw.hex()


def verify_usdc_contract(chain: str, w3: Any) -> dict[str, Any]:
    """Ask the chain whether this chain's `usdc_address` really is USDC.

    Returns ``{"ok": bool, "reason": str, ...}`` and never raises: a settlement
    path should refuse to send on a failed check, not crash on it.

    Worth the round trip because the failure it catches is silent. A wrong but
    well-formed token address does not error — the transfer succeeds against
    whatever contract lives there, or against nothing, and the funds are simply
    gone. Checking `symbol()` and `decimals()` turns that into a refusal.
    """
    cfg = get_chain(chain)
    address = cfg["usdc_address"]
    if not address:
        return {"ok": False, "reason": f"no USDC address configured for {chain!r}"}

    try:
        checksummed = w3.to_checksum_address(address)
        chain_id = w3.eth.chain_id
        if chain_id != cfg["chain_id"]:
            return {
                "ok": False,
                "reason": (
                    f"RPC for {chain!r} reports chain_id {chain_id}, expected "
                    f"{cfg['chain_id']} — the endpoint points at a different network"
                ),
                "chain_id": chain_id,
            }
        symbol = _decode_abi_string(
            w3.eth.call({"to": checksummed, "data": _SELECTOR_SYMBOL})
        )
        decimals = int.from_bytes(
            w3.eth.call({"to": checksummed, "data": _SELECTOR_DECIMALS}), "big"
        )
    except Exception as exc:  # noqa: BLE001 — a check must report, not raise
        return {"ok": False, "reason": f"{type(exc).__name__}: {exc}"}

    if symbol != "USDC" or decimals != 6:
        return {
            "ok": False,
            "reason": (
                f"{address} on {chain!r} reports symbol={symbol!r} decimals={decimals}, "
                "expected 'USDC'/6 — do not send to it"
            ),
            "symbol": symbol,
            "decimals": decimals,
        }

    return {
        "ok": True,
        "reason": "verified against the contract",
        "address": address,
        "symbol": symbol,
        "decimals": decimals,
        "chain_id": chain_id,
    }
