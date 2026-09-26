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
from warden.web3.settlement import (  # noqa: E402
    Preflight,
    deposit_params,
    settlement_preflight,
    trade_id_for,
)
from warden.web3.smart_contract import _contract_address, call_escrow_result  # noqa: E402

JOURNAL = Path(data_path("phase1_deposit_journal.jsonl", "PHASE1_JOURNAL_PATH"))
REQUIRED_MATCHES = 5
DELIVERY_WINDOW_SECONDS = 48 * 3600


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


def summarise(entries: list[dict]) -> dict:
    """One row per escrow — the newest attempt wins, so a retry after a fix
    does not count twice and a later failure is not hidden by an earlier pass."""
    by_escrow: dict[str, dict] = {}
    for e in entries:
        by_escrow[e["escrow_id"]] = e
    matched = [e for e in by_escrow.values() if e["match"]]
    return {
        "escrows": len(by_escrow),
        "matched": len(matched),
        "required": REQUIRED_MATCHES,
        "passed": len(matched) >= REQUIRED_MATCHES,
        "mismatched": [e for e in by_escrow.values() if not e["match"]],
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

    if pre.ok:
        params = deposit_params(pre, buyer, seller, DELIVERY_WINDOW_SECONDS)
    else:
        # Only here: preflight refused and we are testing that the chain agrees.
        # `amount_minor` may be 0 when the refusal happened before conversion.
        params = {
            "tradeId": bytes.fromhex(trade_id_for(row["escrow_id"])[2:]),
            "buyer": buyer,
            "seller": seller,
            "token": pre.token_address,
            "amount": pre.amount_minor,
            "deliveryWindowSeconds": DELIVERY_WINDOW_SECONDS,
        }
        print("\n--force: sending a deposit preflight refused, to see the revert.")

    print("\nSending deposit…")
    res = call_escrow_result(contract, "deposit", params, chain=chain)
    match = bool(pre.ok) == bool(res.ok)
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
        "match": match,
    }
    _append(entry)

    print(f"  on-chain: {'landed' if res.ok else 'reverted'}"
          f"{'  ' + entry['failure'] if entry['failure'] else ''}")
    if entry["tx_hash"]:
        print(f"  tx      : {entry['tx_hash']}")
    print(f"\n{'MATCH' if match else 'MISMATCH'} — preflight said "
          f"{'pass' if pre.ok else 'refuse'}, the chain said "
          f"{'landed' if res.ok else 'reverted'}.")
    if not match:
        print("This is what the gate is for. Do not proceed to Phase 2; the\n"
              "preflight and the chain disagree about this escrow.")
    s = summarise(read_journal())
    print(f"Verified escrows: {s['matched']}/{s['required']}")
    return 0 if match else 3


def cmd_report(_args) -> int:
    s = summarise(read_journal())
    if not s["escrows"]:
        print(f"No runs recorded in {JOURNAL}")
        return 1
    print(f"Escrows attempted : {s['escrows']}")
    print(f"Verdict reproduced: {s['matched']}/{s['required']}")
    for e in s["mismatched"]:
        print(f"  MISMATCH {e['escrow_id']}: preflight "
              f"{'pass' if e['preflight_ok'] else 'refuse'} vs chain "
              f"{'landed' if e['sent_ok'] else 'reverted'}")
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
