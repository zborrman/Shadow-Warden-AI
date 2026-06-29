"""
ANS Bootstrap — Agent Name Service DNS record generator for Shadow Warden AI.

Prints the DNS TXT and SRV records required to register Shadow Warden's marketplace
nodes with the Agent Name Service (ANS) standard (GoDaddy / IETF draft).

Usage:
    python scripts/ans_bootstrap.py                          # dry-run: print records
    python scripts/ans_bootstrap.py --domain shadow-warden-ai.com
    python scripts/ans_bootstrap.py --agent-id did:shadow:abc123 --domain example.com
"""
from __future__ import annotations

import argparse
import json
import os
import sqlite3


def _load_platform_did(db_path: str | None = None) -> str | None:
    """Load the platform agent DID from marketplace SQLite."""
    path = db_path or os.getenv("MARKETPLACE_DB_PATH", "/tmp/warden_marketplace.db")
    try:
        con = sqlite3.connect(path)
        row = con.execute(
            "SELECT agent_id FROM marketplace_agents ORDER BY registered_at ASC LIMIT 1"
        ).fetchone()
        con.close()
        return row[0] if row else None
    except Exception:
        return None


def generate_dns_records(
    domain: str,
    agent_id: str,
    adp_url: str,
    filter_url: str,
    pubkey: str,
) -> dict[str, list[dict]]:
    """
    Returns DNS records in the ANS format.

    TXT _agent.<domain>  — capability advertisement + DID
    SRV _agent._tcp.<domain> — service discovery for M2M agents
    """
    txt_value = " ".join([
        f'did="{agent_id}"',
        f'adp="{adp_url}"',
        f'filter="{filter_url}"',
        'capabilities="marketplace,filter,kya,x402"',
        f'pubkey="{pubkey}"',
    ])

    return {
        "TXT": [
            {
                "name":  f"_agent.{domain}",
                "type":  "TXT",
                "ttl":   300,
                "value": txt_value,
                "note":  "ANS capability advertisement — readable by AI agents before HTTP",
            }
        ],
        "SRV": [
            {
                "name":     f"_agent._tcp.{domain}",
                "type":     "SRV",
                "ttl":      300,
                "priority": 10,
                "weight":   100,
                "port":     443,
                "target":   f"api.{domain}.",
                "note":     "ANS service location — M2M agents use this to find the marketplace endpoint",
            }
        ],
        "CNAME_WELL_KNOWN": [
            {
                "name":  f"_did.{domain}",
                "type":  "TXT",
                "ttl":   3600,
                "value": f'"did:web:{domain}"',
                "note":  "W3C did:web resolution — links DNS identity to DID Document at /.well-known/did.json",
            }
        ],
    }


def print_records(records: dict, domain: str, agent_id: str) -> None:
    print(f"\n{'='*60}")
    print(f"  ANS DNS Records for {domain}")
    print(f"  Platform DID: {agent_id}")
    print(f"{'='*60}\n")

    for _rtype, entries in records.items():
        for entry in entries:
            print(f"[{entry['type']}]  {entry['name']}")
            if entry["type"] == "SRV":
                print(f"  {entry['priority']} {entry['weight']} {entry['port']} {entry['target']}")
            else:
                print(f"  {entry['value']}")
            print(f"  TTL: {entry['ttl']}s")
            print(f"  # {entry['note']}\n")

    print("Registration instructions:")
    print("  1. Add the TXT record to your DNS provider (Cloudflare, Route53, GoDaddy, etc.)")
    print("  2. Add the SRV record so M2M agents can resolve the marketplace endpoint")
    print("  3. Verify: dig TXT _agent." + domain)
    print("  4. Replace REPLACE_WITH_PLATFORM_ED25519_PUBKEY_BASE58 in")
    print("     site/public/.well-known/did.json with your actual platform pubkey")
    print("     (read from warden/marketplace/agent.py generate_platform_keypair())\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate ANS DNS records for Shadow Warden AI")
    parser.add_argument("--domain",   default="shadow-warden-ai.com")
    parser.add_argument("--agent-id", default=None, help="Platform DID (auto-detected from DB if omitted)")
    parser.add_argument("--pubkey",   default="REPLACE_WITH_PLATFORM_ED25519_PUBKEY_BASE58")
    parser.add_argument("--json",     action="store_true", help="Output as JSON")
    args = parser.parse_args()

    agent_id = args.agent_id or _load_platform_did() or f"did:web:{args.domain}"
    adp_url  = f"https://{args.domain}/.well-known/agent.json"
    filter_url = f"https://api.{args.domain}/filter"

    records = generate_dns_records(
        domain=args.domain,
        agent_id=agent_id,
        adp_url=adp_url,
        filter_url=filter_url,
        pubkey=args.pubkey,
    )

    if args.json:
        print(json.dumps(records, indent=2))
    else:
        print_records(records, args.domain, agent_id)


if __name__ == "__main__":
    main()
