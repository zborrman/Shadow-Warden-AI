"""
warden/web3/chains.py
──────────────────────
Multi-chain configuration for Cross-chain Escrow.

Supported networks:
  sepolia           — Ethereum Sepolia testnet (default)
  polygon_amoy      — Polygon Amoy testnet
  arbitrum_sepolia  — Arbitrum Sepolia testnet

All RPC URLs are read from environment variables.  Missing URLs are
tolerated at import time (fail-open); the connector raises at deploy time
if no URL is configured for the requested chain.
"""
from __future__ import annotations

from warden.config import settings

CHAINS: dict[str, dict] = {
    "sepolia": {
        "rpc_url":        settings.sepolia_rpc_url or settings.web3_rpc_url,
        "chain_id":       11155111,
        "currency_symbol": "ETH",
        "block_explorer": "https://sepolia.etherscan.io",
    },
    "polygon_amoy": {
        "rpc_url":        settings.polygon_amoy_rpc_url,
        "chain_id":       80002,
        "currency_symbol": "MATIC",
        "block_explorer": "https://www.oklink.com/amoy",
    },
    "arbitrum_sepolia": {
        "rpc_url":        settings.arbitrum_sepolia_rpc_url,
        "chain_id":       421614,
        "currency_symbol": "ETH",
        "block_explorer": "https://sepolia.arbiscan.io",
    },
}

VALID_CHAINS: frozenset[str] = frozenset(CHAINS.keys())
DEFAULT_CHAIN = "sepolia"


def get_chain(chain: str) -> dict:
    """Return chain config or raise ValueError for unknown chain names."""
    if chain not in CHAINS:
        raise ValueError(
            f"Unknown chain '{chain}'. Valid options: {sorted(VALID_CHAINS)}."
        )
    return CHAINS[chain]


def chain_label(chain: str) -> str:
    """Return a human-readable label for display (e.g. 'Polygon Amoy')."""
    return {
        "sepolia":          "Ethereum Sepolia",
        "polygon_amoy":     "Polygon Amoy",
        "arbitrum_sepolia": "Arbitrum Sepolia",
    }.get(chain, chain)
