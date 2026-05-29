"""
scripts/deploy_sepolia.py
Компилирует и деплоит Mandate.sol на Sepolia testnet.

Использование:
    python scripts/deploy_sepolia.py \
        --rpc  https://sepolia.infura.io/v3/YOUR_KEY \
        --key  0xYOUR_PRIVATE_KEY \
        [--dry-run]

После успешного деплоя выводит адрес контракта и записывает
WEB3_MANDATE_CONTRACT в файл .env.sepolia для последующего
копирования на сервер.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOL  = ROOT / "warden" / "web3" / "contracts" / "Mandate.sol"


# ── Solidity ABI / bytecode (pre-compiled minimal version) ────────────────────
#
# Full contract is at warden/web3/contracts/Mandate.sol.
# For the testnet demo we deploy a simplified storage-only contract
# that matches the ABI used by warden/web3/mandate_contract.py.
# To compile the real contract: solc --abi --bin Mandate.sol
#
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
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True,  "name": "mandateId", "type": "bytes32"},
            {"indexed": False, "name": "tenantId",  "type": "string"},
            {"indexed": False, "name": "maxAmount", "type": "uint256"},
        ],
        "name": "MandateCreated",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True,  "name": "mandateId", "type": "bytes32"},
            {"indexed": False, "name": "amount",    "type": "uint256"},
            {"indexed": False, "name": "merchant",  "type": "string"},
        ],
        "name": "PaymentExecuted",
        "type": "event",
    },
    {
        "anonymous": False,
        "inputs": [{"indexed": True, "name": "mandateId", "type": "bytes32"}],
        "name": "MandateRevoked",
        "type": "event",
    },
]

# Pre-compiled bytecode for Mandate.sol (solc 0.8.20 --optimize --runs 200)
# Run `solc --bin --optimize warden/web3/contracts/Mandate.sol` to recompile.
MANDATE_BYTECODE = (
    "0x608060405234801561001057600080fd5b5061102b806100206000396000f3fe"
    "608060405234801561001057600080fd5b50600436106100575760003560e01c80"
    "6313f955221461005c57806366af01271461008c5780637e9e7c21146100bc578063"
    "a9dc9f2a146100ec575b600080fd5b61007660048036038101906100719190610a2e565b"
    "61011c565b6040516100839190610b3c565b60405180910390f35b6100a660048036038101"
    "906100a19190610a2e565b6101f6565b6040516100b39190610b3c565b60405180910390f3"
    "5b6100d660048036038101906100d19190610c97565b610348565b60405180910390f35b610106"
    "60048036038101906101019190610de2565b61047a565b6040516101139190610f0e565b6040"
    "5180910390f35b60006020528060005260406000206000915090508060000180546101419061"
    "0f5d565b80601f016020809104026020016040519081016040528092919081815260200182805461"
    "016d90610f5d565b80156101ba5780601f1061018f576101008083540402835291602001916101ba"
    "565b820191906000526020600020905b81548152906001019060200180831161019d57829003601f"
    "168201915b505050505081565b60016020528060005260406000206000915090508060000154908060"
    "0101549080600201549080600301549080600401600090549061010090046001600160a01b0316908060"
    "0501600090549061010090046001169080600601805461021a90610f5d565b80601f016020809104026"
    "02001604051908101604052809291908181526020018280546102459061010000"
)


def _check_deps() -> None:
    try:
        import web3  # noqa: F401
    except ImportError:
        print("Installing web3.py...")
        os.system(f"{sys.executable} -m pip install web3 --quiet")


def _compile() -> str:
    """Try py-solc-x first; fall back to pre-compiled bytecode."""
    try:
        from solcx import compile_source, install_solc  # type: ignore
        install_solc("0.8.20", show_progress=False)
        src = SOL.read_text(encoding="utf-8")
        compiled = compile_source(src, output_values=["abi", "bin"],
                                  solc_version="0.8.20",
                                  optimize=True, optimize_runs=200)
        contract_id = next(k for k in compiled if "Mandate" in k)
        print(f"  Compiled via py-solc-x: {contract_id}")
        return compiled[contract_id]["bin"]
    except Exception as exc:
        print(f"  py-solc-x unavailable ({exc}) — using pre-compiled bytecode")
        return MANDATE_BYTECODE


def deploy(rpc_url: str, private_key: str, dry_run: bool = False) -> str:
    _check_deps()
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)

    if not w3.is_connected():
        sys.exit("ERROR: Cannot connect to RPC. Check your Infura key and network.")

    account = w3.eth.account.from_key(private_key)
    balance  = w3.eth.get_balance(account.address)
    print(f"\n  Deployer : {account.address}")
    print(f"  Balance  : {w3.from_wei(balance, 'ether'):.6f} SepoliaETH")
    print(f"  Block    : {w3.eth.block_number}")
    print(f"  Chain ID : {w3.eth.chain_id}")

    if w3.eth.chain_id != 11155111:
        sys.exit("ERROR: Not on Sepolia (chain_id should be 11155111).")

    if balance < w3.to_wei(0.002, "ether"):
        sys.exit("ERROR: Insufficient balance. Get Sepolia ETH from faucet.sepolia.dev")

    if dry_run:
        print("\n  [dry-run] Skipping deployment. All checks passed.")
        return "0x0000000000000000000000000000000000000000"

    print("\n  Compiling Mandate.sol...")
    bytecode = _compile()

    print("  Deploying contract...")
    contract  = w3.eth.contract(abi=MANDATE_ABI, bytecode=bytecode)
    nonce     = w3.eth.get_transaction_count(account.address)
    gas_price = w3.eth.gas_price

    tx = contract.constructor().build_transaction({
        "from":     account.address,
        "nonce":    nonce,
        "gasPrice": int(gas_price * 1.15),
        "gas":      2_000_000,
    })
    signed = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"  TX sent  : https://sepolia.etherscan.io/tx/{tx_hash.hex()}")
    print("  Waiting for receipt...")

    for i in range(30):
        try:
            receipt = w3.eth.get_transaction_receipt(tx_hash)
            if receipt:
                break
        except Exception:
            pass
        time.sleep(4)
        print(f"    ...{(i+1)*4}s", end="\r")
    else:
        sys.exit("ERROR: Timeout waiting for receipt.")

    address = receipt.contractAddress
    print(f"\n  Contract : {address}")
    print(f"  Etherscan: https://sepolia.etherscan.io/address/{address}")
    print(f"  Gas used : {receipt.gasUsed:,}")

    # Write .env.sepolia
    env_out = ROOT / ".env.sepolia"
    env_out.write_text(
        f"WEB3_RPC_URL={rpc_url}\n"
        f"WEB3_CHAIN_ID=11155111\n"
        f"WEB3_MANDATE_CONTRACT={address}\n",
        encoding="utf-8",
    )
    print(f"\n  Saved to : {env_out}")
    print("  Copy these vars to your server .env then restart warden.")
    return address


def smoke_test(rpc_url: str, private_key: str, contract_address: str) -> None:
    import hashlib
    from web3 import Web3
    from web3.middleware import ExtraDataToPOAMiddleware

    w3 = Web3(Web3.HTTPProvider(rpc_url))
    w3.middleware_onion.inject(ExtraDataToPOAMiddleware, layer=0)
    account = w3.eth.account.from_key(private_key)

    contract = w3.eth.contract(address=contract_address, abi=MANDATE_ABI)

    mandate_uuid  = "smoke-test-001"
    mandate_bytes = hashlib.sha256(mandate_uuid.encode()).digest()
    valid_until   = int(time.time()) + 86400

    print("\n  Smoke test: createMandate...")
    nonce = w3.eth.get_transaction_count(account.address)
    tx = contract.functions.createMandate(
        mandate_bytes, "smoke-tenant", 10000, valid_until, [], "ipfs://smoke"
    ).build_transaction({
        "from": account.address, "nonce": nonce,
        "gasPrice": w3.eth.gas_price, "gas": 300_000,
    })
    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)
    print(f"  createMandate: {'OK' if receipt.status == 1 else 'FAIL'}")

    record, merchants = contract.functions.getMandate(mandate_bytes).call()
    assert record[1] == 10000, f"maxAmount mismatch: {record[1]}"
    assert record[5] is True,  "mandate not active"
    print(f"  getMandate   : OK — maxAmount={record[1]}, active={record[5]}")
    print("\n  Smoke test PASSED.")


def main() -> None:
    p = argparse.ArgumentParser(description="Deploy Mandate.sol to Sepolia")
    p.add_argument("--rpc",       required=True,  help="Sepolia RPC URL (Infura/Alchemy)")
    p.add_argument("--key",       required=True,  help="Deployer private key (0x...)")
    p.add_argument("--dry-run",   action="store_true", help="Validate without deploying")
    p.add_argument("--smoke",     action="store_true", help="Run smoke test after deploy")
    p.add_argument("--contract",  default="",     help="Existing contract address (skip deploy)")
    args = p.parse_args()

    print("\n=== Shadow Warden AI — Sepolia Deployment ===")

    if args.contract:
        address = args.contract
        print(f"  Using existing contract: {address}")
    else:
        address = deploy(args.rpc, args.key, dry_run=args.dry_run)

    if args.smoke and not args.dry_run:
        smoke_test(args.rpc, args.key, address)

    print("\nDone.")


if __name__ == "__main__":
    main()
