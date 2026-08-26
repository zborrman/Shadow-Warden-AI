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
import json
import logging
import os
from functools import lru_cache
from pathlib import Path

from warden.observability import Reason, record_failopen
from warden.web3.chains import DEFAULT_CHAIN, get_chain

log = logging.getLogger("warden.web3.smart_contract")

#: Seconds to wait for a receipt before calling the transaction failed.
_TX_TIMEOUT_S = int(os.getenv("ESCROW_TX_TIMEOUT_S", "180"))


def _sim_address(buyer: str, seller: str, listing_id: str, nonce: str, chain: str) -> str:
    """Deterministic contract address simulation — no node required."""
    raw = f"{buyer}:{seller}:{listing_id}:{nonce}:{chain}".encode()
    return "0x" + hashlib.sha256(raw).hexdigest()[:40]


#: Config that turns simulation into settlement. All three are required, per
#: chain, because each answers a different question: the ABI says what the
#: contract exposes, the address says which deployed instance we mean, and the
#: signer says who pays for and authorises the transaction. Two out of three
#: cannot move value, so two out of three must not report that it can.
#:
#:   ESCROW_ABI_PATH        JSON ABI of the deployed escrow contract
#:   ESCROW_CONTRACT_<CHAIN>  e.g. ESCROW_CONTRACT_BASE=0x…
#:   WEB3_SIGNER_KEY        hex private key that signs escrow calls
_ABI_PATH_VAR = "ESCROW_ABI_PATH"
_SIGNER_VAR = "WEB3_SIGNER_KEY"

#: The ABI ships beside this module. It is a build artifact of
#: `contracts/Escrow.sol`, not an operator decision — and `contracts/` is not in
#: the warden image (compose builds with `context: ./warden`), so there was
#: nothing for `ESCROW_ABI_PATH` to point at. The interlock that matters is
#: unchanged: a deployed address and a signing key remain two separate,
#: deliberate decisions, and two out of three still cannot move value.
_PACKAGED_ABI = Path(__file__).with_name("abi") / "escrow.abi.json"


def _abi_path() -> str:
    """The ABI to use: an explicit override, else the packaged one."""
    explicit = os.getenv(_ABI_PATH_VAR, "").strip()
    if explicit:
        return explicit
    return str(_PACKAGED_ABI) if _PACKAGED_ABI.exists() else ""


def _contract_address(chain: str) -> str:
    return os.getenv(f"ESCROW_CONTRACT_{chain.upper()}", "").strip()


@lru_cache(maxsize=4)
def _load_abi(path: str) -> list | None:
    try:
        with open(path, encoding="utf-8") as fh:
            abi = json.load(fh)
        return abi if isinstance(abi, list) else abi.get("abi")
    except Exception as exc:
        log.error("escrow ABI at %s could not be loaded: %s", _ABI_PATH_VAR, exc)
        return None


def settlement_capability(chain: str = DEFAULT_CHAIN) -> dict:
    """Can this deployment move value on `chain`, and if not, exactly why.

    Read by the marketplace manifest so `settlement_mode` describes what the
    software can do rather than what its configuration suggests. Production
    advertised `onchain` for a week on the strength of `BASE_RPC_URL` defaulting
    to the public Base endpoint — a URL that is always present, in front of a
    contract path that always simulated.

    The reason string is part of the answer. "Cannot settle" with no cause is how
    an operator ends up believing it is a network blip.
    """
    def _no(reason: str, detail: str) -> dict:
        return {"can_settle": False, "reason": reason, "detail": detail, "chain": chain}

    try:
        import web3  # noqa: F401,PLC0415
    except Exception:
        return _no("web3_not_installed", "the web3 package is not available in this image")

    if not get_chain(chain).get("rpc_url"):
        return _no("no_rpc", f"no RPC endpoint configured for {chain}")

    abi_path = _abi_path()
    if not abi_path:
        return _no("abi_not_configured",
                   f"{_ABI_PATH_VAR} is unset and no ABI ships with this build")
    if _load_abi(abi_path) is None:
        return _no("abi_unreadable", f"{abi_path} could not be read as an ABI")

    if not _contract_address(chain):
        return _no("no_contract", f"ESCROW_CONTRACT_{chain.upper()} is unset — "
                                  "nothing is deployed on this chain")
    if not os.getenv(_SIGNER_VAR, "").strip():
        return _no("no_signer", f"{_SIGNER_VAR} is unset — no key to sign with")

    return {"can_settle": True, "reason": "", "detail": "", "chain": chain}


def deploy_escrow(
    buyer: str,
    seller: str,
    listing_id: str,
    nonce: str,
    chain: str = DEFAULT_CHAIN,
) -> str:
    """Return the escrow contract address for this trade, as `<address>:<chain>`.

    When settlement is configured, that is the deployed contract named by
    `ESCROW_CONTRACT_<CHAIN>` — one audited instance per chain, not a fresh
    deployment per trade. Deploying per trade needs bytecode in the image and
    costs gas for every listing bought; a singleton escrow holding per-trade
    state is the ordinary shape and the one the operator can actually verify on
    a block explorer.

    Otherwise the deterministic simulated address, as before. It is derived from
    the trade so it is stable across retries, and it is not a real address —
    which is why `settlement_capability()` exists rather than callers guessing
    from the string.
    """
    if settlement_capability(chain)["can_settle"]:
        return f"{_contract_address(chain)}:{chain}"
    return f"{_sim_address(buyer, seller, listing_id, nonce, chain)}:{chain}"


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
    """Call a function on the escrow contract. Returns whether it took effect.

    Two modes, and the difference is the whole point of this module:

    * **Simulated** — settlement is not configured for this chain. Returns True
      as it always has, because the caller's state machine is the only thing
      running and refusing here would break a flow that never claimed to move
      money. `settlement_capability()` is what tells anyone that.
    * **Real** — ABI, address and signer are present. The transaction is built,
      signed and sent, and this returns whether the receipt says it succeeded.
      **Fail-CLOSED**: a revert, a timeout or an unreachable node returns False.
      The stub returned True on every error, which meant an escrow release that
      never happened was indistinguishable from one that did — the failure mode
      that turns a marketplace into a way to lose other people's money.
    """
    cap = settlement_capability(chain)
    if not cap["can_settle"]:
        log.debug("call_escrow %s simulated on %s (%s)", fn_name, chain, cap["reason"])
        return True

    address, _ = strip_chain_suffix(contract_address or _contract_address(chain))
    try:
        from web3 import Web3  # noqa: PLC0415
        w3 = Web3(Web3.HTTPProvider(get_chain(chain)["rpc_url"]))
        if not w3.is_connected():
            log.error("call_escrow %s: %s RPC unreachable — treating as FAILED", fn_name, chain)
            return False

        abi = _load_abi(_abi_path())
        contract = w3.eth.contract(address=Web3.to_checksum_address(address), abi=abi)
        account = w3.eth.account.from_key(os.getenv(_SIGNER_VAR, "").strip())

        fn = getattr(contract.functions, fn_name)(**params)
        tx = fn.build_transaction({
            "from": account.address,
            "nonce": w3.eth.get_transaction_count(account.address),
            "chainId": get_chain(chain)["chain_id"],
        })
        signed = account.sign_transaction(tx)
        tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=_TX_TIMEOUT_S)

        ok = int(receipt.get("status", 0)) == 1
        log.info(
            "call_escrow %s on %s tx=%s status=%s",
            fn_name, chain, tx_hash.hex()[:18], "success" if ok else "REVERTED",
        )
        return ok
    except Exception as exc:
        # Fail-CLOSED on the real path. The caller must be able to tell "the
        # chain accepted this" from "something went wrong on the way there".
        log.error("call_escrow %s on %s FAILED: %s", fn_name, chain, exc)
        record_failopen("escrow_call", Reason.BACKEND_ERROR, exc)
        return False
