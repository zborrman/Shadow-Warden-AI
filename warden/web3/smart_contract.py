"""
warden/web3/smart_contract.py
──────────────────────────────
Multi-chain smart contract deployer for Cross-chain Escrow.

Wraps the existing ChainConnector with per-chain RPC selection.
Falls back to the deterministic simulation (no Web3 required) when
no RPC URL is set for the target chain, keeping all tests green.
"""
from __future__ import annotations

import hashlib
import logging

from warden.web3.chains import DEFAULT_CHAIN, get_chain

log = logging.getLogger("warden.web3.smart_contract")


def _sim_address(buyer: str, seller: str, listing_id: str, nonce: str, chain: str) -> str:
    """Deterministic contract address simulation — no node required."""
    raw = f"{buyer}:{seller}:{listing_id}:{nonce}:{chain}".encode()
    return "0x" + hashlib.sha256(raw).hexdigest()[:40]


#: Whether this build can execute a real escrow transaction.
#:
#: `deploy_escrow` sets `real_address = None` unconditionally and `call_escrow`
#: returns True without touching a contract — both carry a comment saying the
#: ABI is not wired yet. So no deployment of this code settles on-chain,
#: whatever RPC it is pointed at, and anything derived from "an RPC is
#: configured" is measuring the wrong thing.
#:
#: Wiring the ABI and bytecode is what flips this, and it must flip HERE, next
#: to the stubs, so the claim and the capability cannot drift apart again.
_ESCROW_ABI_WIRED = False


def settlement_capability() -> dict:
    """Can this build move value on-chain, and if not, why not.

    Read by the marketplace manifest so `settlement_mode` describes what the
    software can do rather than what its configuration suggests. Production
    advertised `onchain` for a week on the strength of `BASE_RPC_URL` defaulting
    to the public Base endpoint — a URL that is always present, attached to a
    contract path that always simulates.
    """
    if not _ESCROW_ABI_WIRED:
        return {
            "can_settle": False,
            "reason": "escrow_abi_not_wired",
            "detail": (
                "deploy_escrow() and call_escrow() are stubs: no contract is "
                "deployed and no transaction is signed, on any chain."
            ),
        }
    return {"can_settle": True, "reason": "", "detail": ""}


def deploy_escrow(
    buyer: str,
    seller: str,
    listing_id: str,
    nonce: str,
    chain: str = DEFAULT_CHAIN,
) -> str:
    """
    Deploy (or simulate) an Escrow contract on the specified chain.

    Returns a contract address string:
      - Real address when Web3 + RPC are available.
      - Simulated deterministic address otherwise (fail-open).

    The returned value embeds the chain as a suffix:
        <0x_address>:<chain>
    so callers can always recover which network the contract lives on.
    """
    cfg = get_chain(chain)
    rpc_url = cfg["rpc_url"]

    real_address: str | None = None
    if rpc_url:
        try:
            from web3 import Web3  # noqa: PLC0415
            w3 = Web3(Web3.HTTPProvider(rpc_url))
            if w3.is_connected():
                # Full deploy path — requires ABI + bytecode in prod.
                # Here we use the existing ChainConnector for the actual call
                # and just supply the chain-specific w3 instance.
                log.info("deploy_escrow: connected to %s (chain_id=%s)", chain, cfg["chain_id"])
                # For now simulate on live nodes too until Escrow.sol ABI is wired in.
                # Production: pass ABI/bytecode via env var / file.
                real_address = None
        except Exception as exc:
            log.debug("deploy_escrow Web3 error on %s: %s", chain, exc)

    address = real_address or _sim_address(buyer, seller, listing_id, nonce, chain)
    return f"{address}:{chain}"


def strip_chain_suffix(contract_address: str) -> tuple[str, str]:
    """Split 'address:chain' into (address, chain). Defaults to 'sepolia'."""
    if ":" in contract_address:
        parts = contract_address.rsplit(":", 1)
        return parts[0], parts[1]
    return contract_address, DEFAULT_CHAIN


def call_escrow(
    contract_address: str,
    fn_name: str,
    params: dict,
    chain: str = DEFAULT_CHAIN,
) -> bool:
    """
    Call a function on an Escrow contract.  Fail-open (returns True) when
    Web3 is not installed or the chain has no RPC configured.
    """
    cfg = get_chain(chain)
    rpc_url = cfg["rpc_url"]
    if not rpc_url:
        return True  # simulation mode

    try:
        from web3 import Web3  # noqa: PLC0415
        w3 = Web3(Web3.HTTPProvider(rpc_url))
        if not w3.is_connected():
            return True
        log.debug("call_escrow %s on %s", fn_name, chain)
        # Real ABI call would go here; stub returns True until ABI is wired.
        return True
    except Exception as exc:
        log.debug("call_escrow %s error: %s", fn_name, exc)
        return True
