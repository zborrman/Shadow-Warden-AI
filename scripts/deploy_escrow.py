#!/usr/bin/env python3
"""
scripts/deploy_escrow.py — P1a: put the escrow on a testnet and run one trade.

Everything before this proved the contract is well-formed and that it behaves on
a local EVM (`warden/tests/test_escrow_contract_on_evm.py`). A local EVM is a
cooperative machine: no mempool, no gas market, no reorgs, and it runs the
bytecode this repository just compiled rather than bytecode a chain accepted.
This script closes that gap on Base Sepolia, where the money is worthless and
the mistakes are free.

It does three things, each of which can be run alone:

    --check    connect and report what could happen. Sends nothing.
    --deploy   deploy contracts/escrow.bin, arbiter = the signer.
    --trade    run deposit -> deliverAsset -> confirmReceipt with three distinct
               addresses, and assert on token balances afterwards.

Usage:

    export WEB3_SIGNER_KEY=0x...          # a throwaway key with faucet ETH
    python scripts/deploy_escrow.py --check
    python scripts/deploy_escrow.py --deploy --trade

The key is read from the environment and never from argv: an argument is visible
in `ps` and lands in shell history, and a testnet key today is a mainnet key the
moment somebody reuses it.

MAINNET IS REFUSED. `contracts/Escrow.sol` is unaudited and its arbiter is a
single key; there is no flag here that will deploy it to a chain in
`MAINNET_CHAINS`. That is deliberate, and removing the check is a decision that
belongs in a pull request rather than on a command line.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

CONTRACTS = ROOT / "contracts"
DEFAULT_CHAIN = "base_sepolia"

#: The trade this script runs. Six decimals, so 1.00 of a test token.
AMOUNT = 1_000_000
DELIVERY_WINDOW = 48 * 3600

#: Testnet ETH forwarded to the derived buyer and seller so they can send their
#: own transactions. The buyer signs its own `approve`: an escrow whose deposit
#: the operator can authorise on the buyer's behalf is not an escrow.
FUND_WEI_DEFAULT = 300_000_000_000_000  # 0.0003 ETH

#: EIP-170.
MAX_CODE_SIZE = 24_576

#: Where testnet ETH comes from, per chain. Several well-known faucets require a
#: balance on Ethereum *mainnet* before they will dispense play money, and one is
#: unavailable in whole countries; the proof-of-work faucet asks for neither an
#: account nor a prior balance, which is why it is named first for Sepolia.
FAUCETS = {
    "sepolia": "https://sepolia-faucet.pk910.de (proof-of-work, no account)",
    "base_sepolia": "https://portal.cdp.coinbase.com/products/faucet "
                    "(unavailable in some countries), or bridge from Sepolia",
}


def _fail(msg: str) -> None:
    print("\n  FAILED: " + msg)
    sys.exit(1)


def _artifacts(stem: str, subdir: str = "") -> tuple[list, str]:
    base = CONTRACTS / subdir if subdir else CONTRACTS
    abi_p, bin_p = base / (stem + ".abi.json"), base / (stem + ".bin")
    if not abi_p.exists() or not bin_p.exists():
        _fail(stem + " not built - run scripts/build_escrow.sh")
    abi = json.loads(abi_p.read_text(encoding="utf-8"))
    return abi, bin_p.read_text(encoding="utf-8").strip()


def _connect(chain: str, rpc_override: str = ""):
    """Connect, and verify the chain is the one that was asked for.

    The chain id comes from the node, not from the flag. A wrong RPC URL in an
    environment file is the ordinary way a "testnet" deployment lands somewhere
    else, and the node is the only party that can settle the question.
    """
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware

    from warden.web3.chains import MAINNET_CHAINS, get_chain

    if chain in MAINNET_CHAINS:
        _fail(chain + " is a mainnet. Escrow.sol is unaudited; see the module docstring.")

    try:
        meta = get_chain(chain)
    except Exception as exc:
        _fail("chain " + repr(chain) + " is not in the registry: " + str(exc))

    rpc = rpc_override or meta.get("rpc_url") or ""
    if not rpc:
        _fail("no RPC URL for " + chain + " - set the chain's *_RPC_URL, or pass --rpc")

    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    if not w3.is_connected():
        _fail("no response from " + rpc)

    actual, expected = w3.eth.chain_id, meta["chain_id"]
    if actual != expected:
        _fail(rpc + " is chain " + str(actual) + ", but " + chain + " is " + str(expected))

    print(f"  chain      : {chain} (id {actual})")
    print(f"  rpc        : {rpc}")
    print(f"  block      : {w3.eth.block_number}")
    return w3, meta


def _signer_key() -> str:
    key = os.getenv("WEB3_SIGNER_KEY", "").strip()
    return ("0x" + key) if key and not key.startswith("0x") else key


def _signer(w3):
    key = _signer_key()
    if not key:
        _fail("WEB3_SIGNER_KEY is unset. Export a throwaway key funded from a "
              "Base Sepolia faucet; it is never passed as an argument.")
    try:
        return w3.eth.account.from_key(key)
    except Exception as exc:
        _fail("WEB3_SIGNER_KEY is not a valid private key: " + str(exc))


def _derive(w3, base_key: str, label: str):
    """A distinct account, reproducible from the signer key.

    Buyer, seller and arbiter must be three different addresses or the trade
    proves nothing: tokens moving from a key to itself would satisfy every
    assertion below while exercising none of the access control.
    """
    from web3 import Web3

    seed = Web3.keccak(text=base_key + ":" + label + ":shadow-warden-p1a")
    return w3.eth.account.from_key(seed)


def _send(w3, acct, tx, label: str, explorer: str) -> dict:
    tx.setdefault("from", acct.address)
    tx.setdefault("nonce", w3.eth.get_transaction_count(acct.address))
    tx.setdefault("chainId", w3.eth.chain_id)
    if "gas" not in tx:
        try:
            tx["gas"] = int(w3.eth.estimate_gas(tx) * 1.25)
        except Exception as exc:
            _fail(label + ": the gas estimate reverted, so nothing was sent - " + str(exc))

    base = w3.eth.get_block("latest").get("baseFeePerGas") or w3.eth.gas_price
    tx.setdefault("maxPriorityFeePerGas", w3.to_wei(0.001, "gwei"))
    tx.setdefault("maxFeePerGas", base * 2 + tx["maxPriorityFeePerGas"])

    signed = w3.eth.account.sign_transaction(tx, acct.key)
    h = w3.eth.send_raw_transaction(signed.raw_transaction)
    print("  {:<22} 0x{}".format(label, h.hex().removeprefix("0x")))
    rcpt = w3.eth.wait_for_transaction_receipt(h, timeout=180)
    if rcpt["status"] != 1:
        _fail(label + " reverted on chain - " + explorer + "/tx/0x" + h.hex().removeprefix("0x"))
    return rcpt


def cmd_check(w3, meta, args) -> None:
    abi, code = _artifacts("escrow")
    size = len(code.removeprefix("0x")) // 2
    print(f"  bytecode   : {size} bytes")
    if size > MAX_CODE_SIZE:
        _fail("bytecode exceeds the EIP-170 limit; no chain will accept it")
    _artifacts("mock_erc20", "test")

    if not _signer_key():
        print("\n  WEB3_SIGNER_KEY is unset, so nothing further can be checked.")
        hint = FAUCETS.get(args.chain, "a faucet for this chain")
        print("  Fund a throwaway key: " + hint)
        return

    acct = _signer(w3)
    bal = w3.eth.get_balance(acct.address)
    print(f"  signer     : {acct.address}")
    print("  balance    : {} ETH".format(w3.from_wei(bal, "ether")))

    ctor = w3.eth.contract(abi=abi, bytecode=code).constructor(acct.address)
    gas = ctor.estimate_gas({"from": acct.address})
    price = w3.eth.gas_price
    need = (gas + 1_400_000) * price + 2 * args.fund
    print("  deploy gas : {} @ {} gwei".format(gas, w3.from_wei(price, "gwei")))
    print("  need ~     : {} ETH (deploy + trade + funding)".format(w3.from_wei(need, "ether")))
    if bal >= need:
        print("\n  READY - run with --deploy --trade")
    else:
        print("\n  UNDERFUNDED - short {} ETH".format(w3.from_wei(need - bal, "ether")))


def cmd_deploy(w3, meta, args, acct) -> str:
    abi, code = _artifacts("escrow")
    print("\n  Deploying Escrow.sol (arbiter = signer)")
    ctor = w3.eth.contract(abi=abi, bytecode=code).constructor(acct.address)
    rcpt = _send(w3, acct, ctor.build_transaction({"from": acct.address}),
                 "escrow deploy", meta["block_explorer"])
    addr = rcpt["contractAddress"]

    if len(w3.eth.get_code(addr)) < 100:
        _fail("the address holds no code - the deployment did not take")

    on_chain = w3.eth.contract(address=addr, abi=abi).functions.arbiter().call()
    if on_chain != acct.address:
        _fail("the deployed arbiter is " + on_chain + ", not the signer")

    print(f"  escrow     : {addr}")
    print("  explorer   : {}/address/{}".format(meta["block_explorer"], addr))
    return addr


def cmd_trade(w3, meta, args, acct, escrow_addr: str) -> None:
    """One trade, end to end, with the balances checked afterwards."""
    exp = meta["block_explorer"]
    escrow_abi, _ = _artifacts("escrow")
    escrow = w3.eth.contract(address=w3.to_checksum_address(escrow_addr), abi=escrow_abi)

    buyer, seller = _derive(w3, _signer_key(), "buyer"), _derive(w3, _signer_key(), "seller")
    if len({acct.address, buyer.address, seller.address}) != 3:
        _fail("buyer, seller and arbiter collapsed to the same address")
    print(f"\n  buyer      : {buyer.address}")
    print(f"  seller     : {seller.address}")

    print("\n  Deploying a test ERC-20")
    tok_abi, tok_code = _artifacts("mock_erc20", "test")
    rcpt = _send(w3, acct,
                 w3.eth.contract(abi=tok_abi, bytecode=tok_code)
                 .constructor(acct.address).build_transaction({"from": acct.address}),
                 "token deploy", exp)
    token = w3.eth.contract(address=rcpt["contractAddress"], abi=tok_abi)
    print(f"  token      : {token.address}")

    print("\n  Funding the parties")
    for who in (buyer, seller):
        if w3.eth.get_balance(who.address) < args.fund:
            _send(w3, acct, {"to": who.address, "value": args.fund, "gas": 21_000},
                  "fund " + who.address[:10], exp)
    _send(w3, acct, token.functions.mint(buyer.address, AMOUNT)
          .build_transaction({"from": acct.address}), "mint to buyer", exp)

    trade_id = os.urandom(32)
    print(f"\n  Trade 0x{trade_id.hex()}")
    _send(w3, buyer, token.functions.approve(escrow.address, AMOUNT)
          .build_transaction({"from": buyer.address}), "buyer approve", exp)
    _send(w3, acct, escrow.functions.deposit(
        trade_id, buyer.address, seller.address, token.address,
        AMOUNT, DELIVERY_WINDOW).build_transaction({"from": acct.address}), "deposit", exp)

    held = token.functions.balanceOf(escrow.address).call()
    if held != AMOUNT:
        _fail(f"escrow holds {held}, expected {AMOUNT}")
    if token.functions.balanceOf(seller.address).call() != 0:
        _fail("the seller was paid before delivering")

    _send(w3, seller, escrow.functions.deliverAsset(trade_id, os.urandom(32))
          .build_transaction({"from": seller.address}), "seller delivers", exp)
    if token.functions.balanceOf(seller.address).call() != 0:
        _fail("delivery alone moved the funds - only confirmation or the deadline may")

    _send(w3, buyer, escrow.functions.confirmReceipt(trade_id)
          .build_transaction({"from": buyer.address}), "buyer confirms", exp)

    paid = token.functions.balanceOf(seller.address).call()
    left = token.functions.balanceOf(escrow.address).call()
    state = escrow.functions.stateOf(trade_id).call()
    print(f"\n  seller now : {paid} (expected {AMOUNT})")
    print(f"  escrow now : {left} (expected 0)")
    print(f"  state      : {state} (expected 3 = Released)")
    if (paid, left, state) != (AMOUNT, 0, 3):
        _fail("the trade settled somewhere other than where it should have")

    print(f"\n  Settled. {exp}/address/{escrow.address}")
    print("\n  To let the gateway use this instance:")
    print("    ESCROW_ABI_PATH=contracts/escrow.abi.json")
    print(f"    ESCROW_CONTRACT_{args.chain.upper()}={escrow.address}")
    print("    WEB3_SIGNER_KEY=...   (already exported)")
    print("  settlement_mode then reports 'testnet'. It reports 'onchain' only for")
    print("  a chain in MAINNET_CHAINS, which needs the audit first.")


def main() -> None:
    p = argparse.ArgumentParser(description="Deploy the escrow to a testnet and run one trade.")
    p.add_argument("--chain", default=DEFAULT_CHAIN, help="default " + DEFAULT_CHAIN)
    p.add_argument("--rpc", default="", help="override the registry's RPC URL")
    p.add_argument("--check", action="store_true", help="report readiness, send nothing")
    p.add_argument("--deploy", action="store_true", help="deploy the escrow")
    p.add_argument("--trade", action="store_true", help="run one full trade")
    p.add_argument("--escrow", default="", help="use an already-deployed escrow")
    p.add_argument("--fund", type=int, default=FUND_WEI_DEFAULT,
                   help="wei forwarded to the buyer and seller")
    args = p.parse_args()

    if not (args.check or args.deploy or args.trade):
        args.check = True

    started = time.time()
    print(f"\n  Shadow Warden - escrow on {args.chain}\n")
    w3, meta = _connect(args.chain, args.rpc)

    if not (args.deploy or args.trade):
        cmd_check(w3, meta, args)
        return

    acct = _signer(w3)
    print(f"  signer     : {acct.address}")
    print("  balance    : {} ETH".format(w3.from_wei(w3.eth.get_balance(acct.address), "ether")))

    escrow_addr = args.escrow
    if args.deploy:
        escrow_addr = cmd_deploy(w3, meta, args, acct)
    if args.trade:
        if not escrow_addr:
            _fail("--trade needs --deploy, or --escrow 0x...")
        cmd_trade(w3, meta, args, acct, escrow_addr)

    print(f"\n  Done in {time.time() - started:.1f}s\n")


if __name__ == "__main__":
    main()
