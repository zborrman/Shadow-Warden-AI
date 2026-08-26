#!/usr/bin/env python3
"""
scripts/seed_first_party_supply.py — P3.

Twenty first-party listings, each one refusing to exist unless the capability
behind it does.

A two-sided market with zero supply does not bootstrap itself, and the platform's
advantage is that it can credibly be its own first seller. The obvious way to do
that is to write twenty rows into a listings table — and that is the failure this
repository has spent weeks removing everywhere else. Supply that exists in a
database and not in the gateway is a demo, and the fill rate that follows is a
measurement of nothing.

So every entry in CATALOGUE names a `verify` path, and the seeder refuses to
create the listing unless that path is present in the **live** OpenAPI document
of the gateway being seeded. Not the source tree — the running build. A route
that was removed, renamed, or never deployed takes its listing down with it and
is reported as skipped.

What that check does and does not prove, stated plainly: it proves the deployed
gateway serves the route. It does not prove the route works, and it is not a
substitute for `scripts/quickstart_check.py`, which actually calls things. It is
the strongest claim available without side effects on production.

Usage:

    python scripts/seed_first_party_supply.py                       # dry run
    python scripts/seed_first_party_supply.py --base-url URL --api-key KEY
    python scripts/seed_first_party_supply.py ... --commit          # writes

Dry run is the default deliberately: this writes rows to a real marketplace, and
`--commit` should be something you typed on purpose.

Re-running is safe. Each listing carries a deterministic `sku` and the seeder
skips any sku already listed, so a second run adds nothing rather than doubling
the catalogue.
"""
from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Windows consoles default to cp1252 and this script prints a currency-and-arrow
# table. Without this the run dies on an encode error after doing the work.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

TENANT = "shadow-warden"
COMMUNITY = "default"

#: The first-party catalogue. `verify` is the live route that must exist for the
#: listing to be created; `sku` is what makes re-running idempotent.
#:
#: Prices are the untested half. `docs/launch-program.md` says as much: the price
#: list is coherent but has never met a willing buyer, and the first ten
#: transactions are the experiment, not the confirmation.
CATALOGUE: list[dict[str, Any]] = [
    # ── Detection ────────────────────────────────────────────────────────────
    {"sku": "fp-filter-single", "verify": "/filter", "type": "service", "price": 0.001,
     "name": "Prompt injection filter, per call",
     "desc": "Nine-stage pipeline: topology, obfuscation decode, secret redaction, "
             "rules, ML similarity, causal arbitration, reputation."},
    {"sku": "fp-filter-batch", "verify": "/filter/batch", "type": "service", "price": 0.008,
     "name": "Prompt injection filter, batch of 10",
     "desc": "Same pipeline, amortised connection and model load."},
    {"sku": "fp-filter-output", "verify": "/filter/output", "type": "service", "price": 0.001,
     "name": "Model output guard",
     "desc": "Scans what the model said, not only what it was asked."},
    {"sku": "fp-filter-file", "verify": "/filter/file", "type": "service", "price": 0.01,
     "name": "File scanner",
     "desc": "Upload scanning across the supported types at /filter/file/supported-types."},
    {"sku": "fp-filter-multimodal", "verify": "/filter/multimodal", "type": "service",
     "price": 0.02, "name": "Multimodal filter",
     "desc": "Image and text together, for agents that accept both."},

    # ── Document intelligence ────────────────────────────────────────────────
    {"sku": "fp-doc-convert", "verify": "/document-intel/convert", "type": "service",
     "price": 0.005, "name": "Document conversion",
     "desc": "Normalise a document to text; formats listed at /document-intel/formats."},
    {"sku": "fp-doc-convert-scan", "verify": "/document-intel/convert-and-scan",
     "type": "service", "price": 0.012, "name": "Convert and scan",
     "desc": "Conversion with the filter pipeline applied to the result in one call."},
    {"sku": "fp-doc-batch", "verify": "/document-intel/convert-batch", "type": "service",
     "price": 0.05, "name": "Document batch conversion",
     "desc": "Many documents per request."},

    # ── Compliance ───────────────────────────────────────────────────────────
    {"sku": "fp-posture", "verify": "/compliance/posture", "type": "report", "price": 2.50,
     "name": "Compliance posture score",
     "desc": "Current posture across the configured frameworks."},
    {"sku": "fp-posture-gaps", "verify": "/compliance/posture/gaps", "type": "report",
     "price": 5.00, "name": "Compliance gap analysis",
     "desc": "Which controls are unmet, and what evidence is missing."},
    {"sku": "fp-smb-report", "verify": "/compliance/smb-report", "type": "report",
     "price": 9.00, "name": "SMB compliance report",
     "desc": "The SMB governance report; HTML and PDF renderings available."},
    {"sku": "fp-sovereign-check", "verify": "/sovereign/compliance/check", "type": "report",
     "price": 4.00, "name": "Data sovereignty check",
     "desc": "Whether a routing decision satisfies jurisdictional constraints."},
    {"sku": "fp-gsam-score", "verify": "/gsam/compliance/score", "type": "report",
     "price": 3.00, "name": "GSAM compliance score",
     "desc": "Governed staff access posture."},

    # ── Threat intelligence ──────────────────────────────────────────────────
    {"sku": "fp-threat-assess", "verify": "/threat/neutralizer/assess", "type": "service",
     "price": 0.25, "name": "Threat assessment",
     "desc": "Assess a payload or indicator against the neutraliser matrix."},
    {"sku": "fp-threat-matrix", "verify": "/threat/neutralizer/matrix", "type": "signals",
     "price": 15.00, "name": "Threat family matrix",
     "desc": "The sector-by-family matrix behind the assessments."},
    {"sku": "fp-shadow-scan", "verify": "/shadow-ai/scan", "type": "service", "price": 1.00,
     "name": "Shadow AI discovery scan",
     "desc": "Subnet probe and DNS analysis across the known provider list."},
    {"sku": "fp-shadow-providers", "verify": "/shadow-ai/providers", "type": "signals",
     "price": 5.00, "name": "Shadow AI provider feed",
     "desc": "The provider signatures the discovery scan matches against."},
    {"sku": "fp-scan-email", "verify": "/scan/email", "type": "service", "price": 0.01,
     "name": "Email scanner",
     "desc": "Phishing and injection scanning for a single message."},
    {"sku": "fp-scan-extensions", "verify": "/scan/extensions", "type": "service",
     "price": 0.50, "name": "Browser extension risk scan",
     "desc": "Scores installed extensions against the risk database."},

    # ── Explainability ───────────────────────────────────────────────────────
    {"sku": "fp-xai-explain", "verify": "/xai/explain/batch", "type": "report", "price": 0.10,
     "name": "Decision explanation",
     "desc": "Causal chain behind a filter verdict: stage, evidence, counterfactual."},
]


def _fail(msg: str) -> int:
    print(f"\n  FAILED: {msg}")
    return 1


def _client(base_url: str, api_key: str):
    import httpx
    if base_url:
        headers = {"X-API-Key": api_key} if api_key else {}
        return httpx.Client(base_url=base_url.rstrip("/"), headers=headers, timeout=30)
    from fastapi.testclient import TestClient

    import warden.main as m
    return TestClient(m.app, raise_server_exceptions=False)


def _live_paths(client) -> set[str]:
    """Routes the *running* gateway serves.

    Read from the deployed OpenAPI rather than the source tree, because the
    question is what this gateway can sell, not what the repository contains.
    """
    r = client.get("/openapi.json")
    if r.status_code != 200:
        return set()
    return set(r.json().get("paths", {}))


def _sku_of(payload: Any) -> str:
    """Dig the sku out of a tokenized asset.

    Two shapes, because two tokenizers: a service or report carries `sku` at the
    top of its payload, while `signals` wraps whatever it was given in a list.
    Reading only the first shape is why the first version of this function found
    nothing and cheerfully created the whole catalogue a second time.
    """
    if isinstance(payload, dict):
        if payload.get("sku"):
            return str(payload["sku"])
        for entry in payload.get("signals") or []:
            if isinstance(entry, dict) and entry.get("sku"):
                return str(entry["sku"])
    return ""


def _existing_skus(client) -> set[str]:
    """Skus already listed, so a second run is a no-op rather than a duplicate.

    The sku lives on the asset, not the listing — a listing only references an
    asset_id — so this costs one extra GET per listing. At catalogue scale that
    is cheaper than the alternative, which is a market advertising the same
    twenty capabilities four times because the seeder ran on four deploys.
    """
    skus: set[str] = set()
    r = client.get("/marketplace/listings", params={"limit": 50})
    if r.status_code != 200:
        return skus
    for lst in r.json():
        asset_id = lst.get("asset_id")
        if not asset_id:
            continue
        a = client.get(f"/marketplace/assets/{asset_id}")
        if a.status_code != 200:
            continue
        sku = _sku_of((a.json().get("token_data") or {}).get("payload"))
        if sku:
            skus.add(sku)
    return skus


def main() -> int:
    p = argparse.ArgumentParser(description="Seed first-party marketplace supply.")
    p.add_argument("--base-url", default="", help="live gateway; omit for in-process")
    p.add_argument("--api-key", default="", help="X-API-Key for a live gateway")
    p.add_argument("--commit", action="store_true", help="actually create the listings")
    args = p.parse_args()

    client = _client(args.base_url, args.api_key)
    target = args.base_url or "the in-process app"
    mode = "COMMIT" if args.commit else "dry run"
    print(f"\nSeeding first-party supply against {target}  [{mode}]\n")

    live = _live_paths(client)
    if not live:
        return _fail("could not read /openapi.json — cannot verify any capability, "
                     "so nothing will be listed")
    print(f"  gateway serves {len(live)} paths")

    verified = [e for e in CATALOGUE if e["verify"] in live]
    missing = [e for e in CATALOGUE if e["verify"] not in live]
    print(f"  catalogue      {len(CATALOGUE)} entries -> {len(verified)} verified, "
          f"{len(missing)} skipped")
    for e in missing:
        print(f"    SKIP {e['sku']:<24} {e['verify']} is not served here")
    if not verified:
        return _fail("no catalogue entry matched a live route")

    already = _existing_skus(client) if args.commit else set()
    todo = [e for e in verified if e["sku"] not in already]
    if already:
        print(f"  already listed {len(verified) - len(todo)}")

    if not args.commit:
        print("\n  Would list:")
        for e in todo:
            print(f"    {e['price']:>8.3f}  {e['sku']:<24} {e['name']}")
        print(f"\n  {len(todo)} listings. Re-run with --commit to create them.")
        return 0

    if not todo:
        print("\n  Nothing to do — every verified sku is already listed.")
        return 0

    # ── Registration ─────────────────────────────────────────────────────────
    # After the skip check, deliberately: registering first meant a no-op run
    # still created a seller agent, so re-running left a trail of empty agents.
    reg = client.post("/marketplace/register", json={
        "tenant_id": TENANT, "community_id": COMMUNITY,
        "public_key": uuid.uuid4().hex,
    })
    if reg.status_code >= 400:
        return _fail(f"register returned {reg.status_code}: {reg.text[:200]}")
    agent_id = reg.json().get("agent_id", "")
    if not agent_id:
        return _fail("register returned no agent_id")
    print(f"\n  seller agent   {agent_id[:48]}")

    created, failed = 0, 0
    for e in todo:
        asset = client.post("/marketplace/assets", json={
            "tenant_id": TENANT, "seller_agent_id": agent_id,
            "asset_type": e["type"],
            "raw_data": {"sku": e["sku"], "name": e["name"], "description": e["desc"],
                         "endpoint": e["verify"], "seller": "first-party"},
        })
        if asset.status_code >= 400:
            print(f"    FAIL {e['sku']:<24} asset {asset.status_code}")
            failed += 1
            continue
        asset_id = asset.json().get("asset_id", "")

        listing = client.post("/marketplace/listings", json={
            "asset_id": asset_id, "seller_agent_id": agent_id,
            "community_id": COMMUNITY, "tenant_id": TENANT,
            "asset_type": e["type"], "price_usd": e["price"],
        })
        if listing.status_code >= 400:
            print(f"    FAIL {e['sku']:<24} listing {listing.status_code}: "
                  f"{listing.text[:120]}")
            failed += 1
            continue
        print(f"    OK   {e['sku']:<24} ${e['price']:.3f}  "
              f"{listing.json().get('listing_id', '')[:24]}")
        created += 1

    print(f"\n  created {created}, failed {failed}, skipped {len(missing)}")
    live_now = client.get("/marketplace/listings", params={"limit": 50})
    if live_now.status_code == 200:
        print(f"  the market now advertises {len(live_now.json())} listings")
    print("\n  Supply is not demand. P3's exit needs ten agents that transacted and")
    print("  one trade where neither side is first-party; this is neither.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
