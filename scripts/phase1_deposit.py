#!/usr/bin/env python3
"""
scripts/phase1_deposit.py — the Phase 1 exit gate, run by hand.

`docs/onchain-settlement-design.md` §7 lets settlement leave Phase 1 only when,
"for at least 5 escrows, preflight's verdict was reproduced by a manual
`deposit` from the operator's own machine". That is a deliberately manual step:
it is where a preflight that passes but shouldn't gets caught, before it can
cost anything. This script makes each run one command and keeps the evidence,
so the gate is counted rather than remembered.

What "reproduced" means here, and why both directions count:

  * preflight said **ok**      → the deposit must land.
  * preflight said **refuse**  → the deposit must revert. Checking only the
    happy path would pass a preflight that refuses everything.

`deposit_params()` refuses to build arguments for a failed preflight, which is
right in the product and wrong for this gate — so `--force` builds them here
instead, and only here. It exists to prove a refusal was correct, never to
settle a trade.

Usage (Base Sepolia testnet; nothing below touches mainnet):

    export WEB3_SIGNER_KEY=0x…            # the buyer's key, on your machine
    export ESCROW_CONTRACT_BASE_SEPOLIA=0x…
    python scripts/phase1_deposit.py list
    python scripts/phase1_deposit.py check   <escrow_id>
    python scripts/phase1_deposit.py deposit <escrow_id>
    python scripts/phase1_deposit.py deposit <escrow_id> --force   # prove a refusal
    python scripts/phase1_deposit.py report

`check` sends nothing. `deposit` sends one transaction and records the outcome
in the journal next to the module databases.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from warden.config import data_path  # noqa: E402
from warden.marketplace.agent import get_agent  # noqa: E402
from warden.marketplace.escrow import _conn  # noqa: E402
from warden.web3.chains import get_chain, verify_usdc_contract  # noqa: E402
from warden.web3.settlement import (  # noqa: E402
    Preflight,
    deposit_params,
    settlement_preflight,
    to_minor_units,
    trade_id_for,
)
from warden.web3.smart_contract import (  # noqa: E402
    _abi_path,
    _contract_address,
    _error_selectors,
    _load_abi,
    call_escrow_result,
)

JOURNAL = Path(data_path("phase1_deposit_journal.jsonl", "PHASE1_JOURNAL_PATH"))
REQUIRED_MATCHES = 5
DELIVERY_WINDOW_SECONDS = 48 * 3600

#: Refusals the contract can be asked to repeat. Each is a fact about chain
#: state that `deposit` itself trips over. Everything else preflight refuses is
#: policy or configuration — the trade cap, an unconfigured chain, a malformed
#: address — which the contract has no opinion on: forcing past the cap would
#: *land*, moving more than the cap allows, and be logged as a mismatch.
CHAIN_REPRODUCIBLE_REFUSALS = frozenset({"insufficient_allowance", "insufficient_balance"})

#: Exception types web3 raises when a node executed the call and it reverted.
#: Anything else — `MismatchedABI`, a timeout, an unreachable RPC — means the
#: contract never judged the deposit, so it cannot have agreed with preflight.
_REVERT_EXCEPTIONS = frozenset({"ContractLogicError", "ContractCustomError", "ContractPanicError"})


# ── escrow lookup ─────────────────────────────────────────────────────────────

def _escrows(escrow_id: str | None = None) -> list[dict]:
    sql = ("SELECT escrow_id, buyer_agent, seller_agent, amount_usd, chain, status, "
           "preflight_verdict FROM marketplace_escrow")
    args: tuple = ()
    if escrow_id:
        sql += " WHERE escrow_id = ?"
        args = (escrow_id,)
    with _conn() as con:
        return [dict(r) for r in con.execute(sql + " ORDER BY rowid", args)]


def _address_for(agent_id: str, override: str) -> str:
    """The agent's bound payout address, or the one the operator passed."""
    if override:
        return override
    agent = get_agent(agent_id)
    return getattr(agent, "payout_address", "") or ""


def _preflight_for(row: dict, buyer: str, seller: str) -> Preflight:
    return settlement_preflight(
        escrow_id=row["escrow_id"],
        amount_usd=float(row["amount_usd"]),
        buyer_address=buyer,
        seller_address=seller,
        chain=row["chain"],
    )


def _print_verdict(pre: Preflight) -> None:
    print(f"  verdict : {'PASS' if pre.ok else 'REFUSE'}"
          f"{'' if pre.ok else '  (' + pre.reason + ')'}")
    if pre.detail:
        print(f"  detail  : {pre.detail}")
    print(f"  trade   : {pre.trade_id}  amount_minor={pre.amount_minor}")
    for c in pre.checks:
        print(f"    {'ok  ' if c.ok else 'FAIL'}  {c.name:24} {c.detail}")


# ── journal ───────────────────────────────────────────────────────────────────

def _append(entry: dict) -> None:
    JOURNAL.parent.mkdir(parents=True, exist_ok=True)
    with JOURNAL.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def read_journal() -> list[dict]:
    if not JOURNAL.exists():
        return []
    return [json.loads(ln) for ln in JOURNAL.read_text(encoding="utf-8").splitlines() if ln.strip()]


def chain_rejected(res, abi_errors: frozenset[str] | set[str]) -> bool:
    """Whether the contract itself refused the call — not merely that it failed.

    A refusal is only reproduced when the chain executed the deposit and said
    no: a mined transaction with status 0, the escrow's own custom error, or a
    revert web3 reports as such. The first version counted any failure, so a
    forced deposit whose arguments could not even be encoded (`MismatchedABI`,
    nothing sent, no transaction hash) was journalled as the chain agreeing.
    """
    if getattr(res, "ok", False) or getattr(res, "simulated", False):
        return False
    error = getattr(res, "error", "") or ""
    if getattr(res, "tx_hash", "") and error == "reverted":
        return True
    return error in abi_errors or error in _REVERT_EXCEPTIONS


def counts(entry: dict) -> bool:
    """Whether one journal entry is a reproduced verdict.

    A refusal needs `chain_rejected`: entries written before that field existed
    recorded any failure as a revert, and are not evidence of anything.
    """
    if not entry.get("match"):
        return False
    return bool(entry.get("preflight_ok")) or bool(entry.get("chain_rejected"))


def forced_params(escrow_id: str, amount_usd: float, buyer: str, seller: str,
                  token: str, decimals: int) -> dict:
    """The deposit preflight refused, built in full so the contract can judge it.

    A refused `Preflight` carries no token and no amount — it stopped before
    recording them — so building from it sent `token=""`, which web3 rejects
    locally. These are the arguments a passing preflight would have produced.
    """
    return {
        "tradeId": bytes.fromhex(trade_id_for(escrow_id)[2:]),
        "buyer": buyer,
        "seller": seller,
        "token": token,
        "amount": to_minor_units(amount_usd, decimals),
        "deliveryWindowSeconds": DELIVERY_WINDOW_SECONDS,
    }


def summarise(entries: list[dict]) -> dict:
    """One row per escrow — the newest attempt wins, so a retry after a fix
    does not count twice and a later failure is not hidden by an earlier pass."""
    by_escrow: dict[str, dict] = {}
    for e in entries:
        by_escrow[e["escrow_id"]] = e
    matched = [e for e in by_escrow.values() if counts(e)]
    return {
        "escrows": len(by_escrow),
        "matched": len(matched),
        "required": REQUIRED_MATCHES,
        "passed": len(matched) >= REQUIRED_MATCHES,
        "mismatched": [e for e in by_escrow.values() if not e["match"]],
        # Matched on paper, but the chain never judged it — see `counts`.
        "unproven": [e for e in by_escrow.values() if e["match"] and not counts(e)],
    }


# ── commands ──────────────────────────────────────────────────────────────────

def cmd_list(_args) -> int:
    rows = _escrows()
    if not rows:
        print("No escrows. Phase 1 has nothing to verify until trades exist —\n"
              "create them on a gateway pointed at the same chain first.")
        return 1
    print(f"{'escrow_id':26} {'status':18} {'amount':>9}  chain          preflight")
    for r in rows:
        print(f"{r['escrow_id']:26} {r['status']:18} {r['amount_usd']:9.2f}  "
              f"{r['chain']:14} {r['preflight_verdict'] or '—'}")
    return 0


def cmd_check(args) -> int:
    rows = _escrows(args.escrow_id)
    if not rows:
        print(f"No escrow {args.escrow_id!r}")
        return 1
    row = rows[0]
    buyer = _address_for(row["buyer_agent"], args.buyer)
    seller = _address_for(row["seller_agent"], args.seller)
    if not buyer or not seller:
        print("Buyer or seller has no bound payout address. Pass --buyer/--seller.")
        return 1
    print(f"{row['escrow_id']}  {row['amount_usd']:.2f} USD on {row['chain']}")
    _print_verdict(_preflight_for(row, buyer, seller))
    print("\nNothing was sent.")
    return 0


def cmd_deposit(args) -> int:
    rows = _escrows(args.escrow_id)
    if not rows:
        print(f"No escrow {args.escrow_id!r}")
        return 1
    row = rows[0]
    chain = row["chain"]
    contract = _contract_address(chain)
    if not contract:
        print(f"ESCROW_CONTRACT_{chain.upper()} is not set — nothing to call.")
        return 1

    buyer = _address_for(row["buyer_agent"], args.buyer)
    seller = _address_for(row["seller_agent"], args.seller)
    if not buyer or not seller:
        print("Buyer or seller has no bound payout address. Pass --buyer/--seller.")
        return 1

    pre = _preflight_for(row, buyer, seller)
    print(f"{row['escrow_id']}  {row['amount_usd']:.2f} USD on {chain}")
    _print_verdict(pre)

    if not pre.ok and not args.force:
        print("\nPreflight refuses, so nothing was sent. To prove the refusal is\n"
              "real, re-run with --force: the deposit must then revert.")
        return 2

    if not pre.ok and pre.reason not in CHAIN_REPRODUCIBLE_REFUSALS:
        print(f"\n{pre.reason!r} is a policy or configuration refusal; the contract\n"
              "cannot reproduce it, and forcing past it would move value the\n"
              "refusal exists to stop. Only "
              f"{', '.join(sorted(CHAIN_REPRODUCIBLE_REFUSALS))} can be forced.")
        return 2

    if pre.ok:
        params = deposit_params(pre, buyer, seller, DELIVERY_WINDOW_SECONDS)
    else:
        # Only here: preflight refused and we are testing that the chain agrees.
        from web3 import Web3  # noqa: PLC0415

        verdict = verify_usdc_contract(chain, Web3(Web3.HTTPProvider(get_chain(chain)["rpc_url"])))
        if not verdict.get("ok"):
            print(f"Cannot build the forced deposit: {verdict.get('reason', '')}")
            return 1
        params = forced_params(
            row["escrow_id"], float(row["amount_usd"]), buyer, seller,
            Web3.to_checksum_address(get_chain(chain)["usdc_address"]),
            int(verdict.get("decimals", 6)),
        )
        print("\n--force: sending a deposit preflight refused, to see the revert.")

    print("\nSending deposit…")
    res = call_escrow_result(contract, "deposit", params, chain=chain)
    rejected = chain_rejected(res, set(_error_selectors(_load_abi(_abi_path())).values()))
    # A pass is reproduced by a real landing; a refusal by the contract's own no.
    match = (res.ok and not res.simulated) if pre.ok else rejected
    entry = {
        "escrow_id": row["escrow_id"],
        "at": datetime.now(UTC).isoformat(timespec="seconds"),
        "chain": chain,
        "preflight_ok": bool(pre.ok),
        "preflight_reason": pre.reason,
        "sent_ok": bool(res.ok),
        "failure": getattr(res, "reason", "") or getattr(res, "error", ""),
        "tx_hash": getattr(res, "tx_hash", "") or "",
        "forced": bool(args.force),
        "chain_rejected": rejected,
        "match": match,
    }
    _append(entry)

    outcome = _outcome(entry)
    print(f"  on-chain: {outcome}"
          f"{'  ' + entry['failure'] if entry['failure'] else ''}")
    if entry["tx_hash"]:
        print(f"  tx      : {entry['tx_hash']}")
    print(f"\n{'MATCH' if match else 'MISMATCH'} — preflight said "
          f"{'pass' if pre.ok else 'refuse'}, the chain {outcome}.")
    if not match and not res.ok and not rejected:
        print("The contract never judged this deposit, so nothing was reproduced.\n"
              "Fix the cause above and run it again; this run does not count.")
    elif not match:
        print("This is what the gate is for. Do not proceed to Phase 2; the\n"
              "preflight and the chain disagree about this escrow.")
    s = summarise(read_journal())
    print(f"Verified escrows: {s['matched']}/{s['required']}")
    return 0 if match else 3


def _outcome(entry: dict) -> str:
    if entry.get("sent_ok"):
        return "landed"
    if entry.get("chain_rejected"):
        return "reverted"
    return "never judged it (failed before the contract)"


def cmd_report(_args) -> int:
    s = summarise(read_journal())
    if not s["escrows"]:
        print(f"No runs recorded in {JOURNAL}")
        return 1
    print(f"Escrows attempted : {s['escrows']}")
    print(f"Verdict reproduced: {s['matched']}/{s['required']}")
    for e in s["mismatched"]:
        print(f"  MISMATCH {e['escrow_id']}: preflight "
              f"{'pass' if e['preflight_ok'] else 'refuse'} vs chain {_outcome(e)}")
    for e in s["unproven"]:
        print(f"  UNPROVEN {e['escrow_id']}: a refusal journalled without the chain's\n"
              "           own answer — re-run it with --force")
    print("\nPhase 1 exit: " + ("MET — §7's five are on the record."
                                if s["passed"] else "not yet met."))
    return 0 if s["passed"] else 1


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="escrows and their recorded preflight verdicts")
    for name, help_text in (("check", "run preflight, send nothing"),
                            ("deposit", "run preflight, then send one deposit")):
        sp = sub.add_parser(name, help=help_text)
        sp.add_argument("escrow_id")
        sp.add_argument("--buyer", default="", help="override the bound payout address")
        sp.add_argument("--seller", default="", help="override the bound payout address")
        if name == "deposit":
            sp.add_argument("--force", action="store_true",
                            help="send even though preflight refused, to prove it reverts")
    sub.add_parser("report", help="whether §7's five verified escrows exist")
    args = p.parse_args()
    return {"list": cmd_list, "check": cmd_check,
            "deposit": cmd_deposit, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
