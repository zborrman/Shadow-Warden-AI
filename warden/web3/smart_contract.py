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
from dataclasses import dataclass
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


@dataclass(frozen=True)
class EscrowCallResult:
    """What one escrow call did, not just whether it did.

    `call_escrow` answered with a bool and kept the transaction hash to itself
    (it logged the first 18 characters). An operator could not look a
    transition up on a block explorer, and a retry had no way to ask the chain
    what the previous attempt achieved — its only move was to send again.
    """
    ok: bool
    #: Full 0x-prefixed hash; "" when simulated or when nothing was sent.
    tx_hash: str = ""
    #: Decoded custom-error name (e.g. "WrongState"), or the exception type.
    error: str = ""
    simulated: bool = False
    #: A `deposit` refused with `TradeExists()`: the trade is already funded.
    already_funded: bool = False


# Custom errors whose selector means the call's goal state already holds.
# Only `deposit` qualifies: `TradeExists()` is exactly "this trade id is
# funded", and the trade id is keccak("shadow-warden:escrow:" + escrow_id), so
# it can only be ours. Every other revert is a real refusal.
_ALREADY_DONE = {("deposit", "TradeExists")}


def _error_selectors(abi: list | None) -> dict[bytes, str]:
    """Map 4-byte selector → custom error name, from the ABI itself."""
    from web3 import Web3

    out: dict[bytes, str] = {}
    for entry in abi or []:
        if entry.get("type") != "error":
            continue
        signature = f"{entry['name']}({','.join(i['type'] for i in entry.get('inputs', []))})"
        out[bytes(Web3.keccak(text=signature)[:4])] = entry["name"]
    return out


def _decode_custom_error(exc: BaseException, abi: list | None) -> str:
    """Name the contract's custom error behind *exc*, or "" if it is not one.

    Matched against the ABI's own error entries rather than a hand-kept table —
    a second copy of a contract's vocabulary is how this codebase once shipped an
    enum written out twice that disagreed with itself.

    The revert data reaches here in more than one encoding, and the first
    version of this function knew only one of them. Against a real node, web3
    raises `ContractCustomError` with the selector as hex (`0x822b55c5`). The
    local EVM this is tested on raises `TransactionFailed` with the selector as a
    Python bytes-repr inside a message (`execution reverted: b'\x82+U\xc5'`).
    A decoder that recognised only hex returned "" for a genuine `TradeExists`
    revert from the compiled contract — found by running it against one, not by
    reading it. All three forms are checked: hex, raw bytes, and bytes-repr.
    """
    selectors = _error_selectors(abi)
    if not selectors:
        return ""

    blobs: list[bytes] = []
    texts: list[str] = []
    for part in (getattr(exc, "data", None), *getattr(exc, "args", ()), str(exc)):
        if isinstance(part, (bytes, bytearray)):
            blobs.append(bytes(part))
        elif part is not None:
            texts.append(str(part))
    lowered = [t.lower() for t in texts]

    for selector, name in selectors.items():
        hex_form = "0x" + selector.hex()
        repr_form = repr(selector)[2:-1]          # b'+UÅ' → +UÅ
        if any(selector in b for b in blobs):
            return name
        if any(hex_form in t for t in lowered):
            return name
        if any(repr_form in t for t in texts):
            return name
    return ""


def call_escrow_result(
    contract_address: str,
    fn_name: str,
    params: dict,
    chain: str = DEFAULT_CHAIN,
) -> EscrowCallResult:
    """Call a function on the escrow contract and report what happened.

    Two modes, and the difference is the whole point of this module:

    * **Simulated** — settlement is not configured for this chain. Reports
      success as it always has, because the caller's state machine is the only
      thing running and refusing here would break a flow that never claimed to
      move money. `settlement_capability()` is what tells anyone that.
    * **Real** — ABI, address and signer are present. The transaction is built,
      signed and sent, and the receipt decides. **Fail-CLOSED**: a revert, a
      timeout or an unreachable node is a failure.

    One revert is not a failure. `deposit` reverting `TradeExists()` means the
    trade is already funded — typically because a previous attempt landed and
    its receipt was lost to a timeout. Reading that as a failure turned one
    network hiccup into a permanently stuck escrow: funds held by the contract,
    the gateway record left in `pending_deposit`, and every retry refused
    (docs/onchain-settlement-design.md §4).
    """
    cap = settlement_capability(chain)
    if not cap["can_settle"]:
        log.debug("call_escrow %s simulated on %s (%s)", fn_name, chain, cap["reason"])
        return EscrowCallResult(ok=True, simulated=True)

    address, _ = strip_chain_suffix(contract_address or _contract_address(chain))
    abi = None
    try:
        from web3 import Web3  # noqa: PLC0415
        w3 = Web3(Web3.HTTPProvider(get_chain(chain)["rpc_url"]))
        if not w3.is_connected():
            log.error("call_escrow %s: %s RPC unreachable — treating as FAILED", fn_name, chain)
            return EscrowCallResult(ok=False, error="rpc_unreachable")

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
        sent = w3.eth.send_raw_transaction(signed.raw_transaction)
        tx_hash = "0x" + sent.hex().removeprefix("0x")
        receipt = w3.eth.wait_for_transaction_receipt(sent, timeout=_TX_TIMEOUT_S)

        ok = int(receipt.get("status", 0)) == 1
        log.info(
            "call_escrow %s on %s tx=%s status=%s",
            fn_name, chain, tx_hash, "success" if ok else "REVERTED",
        )
        return EscrowCallResult(ok=ok, tx_hash=tx_hash, error="" if ok else "reverted")
    except Exception as exc:
        result = classify_call_failure(fn_name, exc, abi)
        if result.ok:
            log.info("call_escrow %s on %s: %s — trade already funded, treating as done",
                     fn_name, chain, result.error)
            return result
        # Fail-CLOSED on the real path. The caller must be able to tell "the
        # chain accepted this" from "something went wrong on the way there".
        log.error("call_escrow %s on %s FAILED: %s", fn_name, chain, result.error)
        record_failopen("escrow_call", Reason.BACKEND_ERROR, exc)
        return result


def classify_call_failure(fn_name: str, exc: BaseException, abi: list | None) -> EscrowCallResult:
    """Decide what an exception from an escrow call means. Pure: no chain access.

    Split out so the decision can be tested against a genuine revert produced by
    the compiled contract, rather than against a hand-built exception that only
    agrees with whoever wrote it.
    """
    name = _decode_custom_error(exc, abi)
    if (fn_name, name) in _ALREADY_DONE:
        return EscrowCallResult(ok=True, error=name, already_funded=True)
    return EscrowCallResult(ok=False, error=name or type(exc).__name__)


def call_escrow(
    contract_address: str,
    fn_name: str,
    params: dict,
    chain: str = DEFAULT_CHAIN,
) -> bool:
    """Whether an escrow call took effect. See :func:`call_escrow_result`."""
    return call_escrow_result(contract_address, fn_name, params, chain).ok
