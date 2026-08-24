#!/usr/bin/env python3
"""
scripts/quickstart_check.py — run the quickstart and report what actually happens.

`docs/quickstart.md` claims a foreign agent can register, publish a listing, and
be paid, in ten minutes. A quickstart nobody executes is a claim, and this
repository has a history of those: a site advertising `pip install` for a package
that 404s, a manifest advertising on-chain settlement over a testnet RPC, a gate
that passed on zero rows. So the document and this script ship together, and the
document states what this script reports.

It performs the documented steps in order and prints one line per step with the
status code and what it means. It does not assert success: the point is to show
which steps work today and which are simulated, so the doc can say so plainly.

    python scripts/quickstart_check.py                       # in-process app
    python scripts/quickstart_check.py --base-url URL --api-key KEY

**Against a live gateway it writes real rows** — an agent, a listing, a purchase.
Production marketplace tables are empty by design and the capability matrix cites
that emptiness as evidence, so do not point this at production unless you intend
those rows to exist and are prepared to say so.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from typing import Any

_SIM = "quickstart-check"


def _client(base_url: str, api_key: str):
    if base_url:
        import httpx
        return httpx.Client(
            base_url=base_url.rstrip("/"),
            headers={"X-API-Key": api_key} if api_key else {},
            timeout=30,
        )
    os.environ.setdefault("ALLOW_UNAUTHENTICATED", "true")
    os.environ.setdefault("WARDEN_API_KEY", "")
    os.environ.setdefault("REDIS_URL", "memory://")
    from fastapi.testclient import TestClient

    import warden.main as main
    return TestClient(main.app)


def _show(step: str, resp: Any, note: str = "") -> dict:
    code = getattr(resp, "status_code", 0)
    try:
        body = resp.json()
    except Exception:
        body = {"raw": getattr(resp, "text", "")[:120]}
    ok = 200 <= code < 300
    mark = "ok  " if ok else "FAIL"
    tail = f" - {note}" if note else ""
    print(f"  [{mark}] {step:<34} {code}{tail}")
    if not ok:
        print(f"         {json.dumps(body)[:200]}")
    return body if isinstance(body, dict) else {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="", help="live gateway; omit for in-process")
    ap.add_argument("--api-key", default=os.getenv("WARDEN_API_KEY", ""))
    args = ap.parse_args()

    tenant = f"{_SIM}-{uuid.uuid4().hex[:8]}"
    client = _client(args.base_url, args.api_key)
    print(f"\nQuickstart against {args.base_url or 'the in-process app'} (tenant {tenant})\n")

    # ── 1. Discovery — what does this market say it is? ──────────────────────
    proto = _show("GET /marketplace/protocol", client.get("/marketplace/protocol"))
    escrow = proto.get("escrow", {})
    settlement = escrow.get("settlement_mode", "?")
    print(f"         settlement_mode={settlement} chains={escrow.get('chains')}")
    if settlement != "onchain":
        print("         NOTE: value does not move on this deployment; see the"
              " capability matrix before promising a customer otherwise.")

    # ── 2. Register an agent ─────────────────────────────────────────────────
    reg = _show("POST /marketplace/register", client.post(
        "/marketplace/register",
        json={"tenant_id": tenant, "community_id": "default",
              "public_key": uuid.uuid4().hex},
    ))
    agent_id = reg.get("agent_id") or reg.get("did") or ""
    if not agent_id:
        print("\n  Stopped: no agent id returned, so nothing downstream can be tried.")
        return 1
    print(f"         agent_id={agent_id[:48]}")

    # ── 3. Register the asset being sold ─────────────────────────────────────
    #
    # A listing points at an asset; it does not carry one. The first version of
    # this script guessed otherwise and got a 422 on `asset_id`, which is the
    # error a quickstart written from the source and never executed ships with.
    asset = _show("POST /marketplace/assets", client.post(
        "/marketplace/assets",
        json={"tenant_id": tenant, "seller_agent_id": agent_id,
              "asset_type": "rule",
              "raw_data": {"pattern": "ignore (all )?previous instructions",
                           "note": "created by scripts/quickstart_check.py"}},
    ))
    asset_id = asset.get("asset_id") or asset.get("id") or ""
    if not asset_id:
        print("\n  Stopped: no asset id returned.")
        return 1

    # ── 4. Publish a listing for it ──────────────────────────────────────────
    listing = _show("POST /marketplace/listings", client.post(
        "/marketplace/listings",
        json={"asset_id": asset_id, "seller_agent_id": agent_id,
              "community_id": "default", "tenant_id": tenant,
              "asset_type": "rule", "price_usd": 1.0},
    ))
    listing_id = listing.get("listing_id") or listing.get("id") or ""
    if not listing_id:
        print("\n  Stopped: no listing id returned.")
        return 1

    # ── 5. Buy it ────────────────────────────────────────────────────────────
    buy = _show(
        "POST /listings/{id}/purchase",
        client.post(f"/marketplace/listings/{listing_id}/purchase",
                    json={"buyer_agent_id": agent_id},
                    headers={"Idempotency-Key": uuid.uuid4().hex}),
        note="Idempotency-Key is mandatory (FT-3)",
    )

    # ── 6. What settled? ─────────────────────────────────────────────────────
    print("\nWhat that produced")
    print(f"  purchase state : {buy.get('status', buy.get('state', '?'))}")
    amount = buy.get("price_paid", buy.get("price_usd", buy.get("amount")))
    if amount is None:
        # Say which keys came back rather than printing a bare "?": the next
        # person needs to know whether the field moved or the purchase is silent
        # about what it cost.
        print(f"  amount         : not reported; keys={sorted(buy)[:8]}")
    else:
        print(f"  amount         : {amount}")
    print(f"  settlement     : {settlement}"
          + ("  <- real value moved" if settlement == "onchain"
             else "  <- state machine only, no value moved"))
    print("\nRerun with --base-url to check a live gateway.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
