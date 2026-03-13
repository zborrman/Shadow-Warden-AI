#!/usr/bin/env python3
"""
gtm/apollo_scraper.py
━━━━━━━━━━━━━━━━━━━━━
Apollo.io lead scraper for Shadow Warden AI.

Searches for MSP decision-makers (CTO / CISO / IT Director / Founder),
pages through results, deduplicates, and writes a clean CSV ready for
Instantly.ai / Lemlist import.

Usage:
  export APOLLO_API_KEY=your_key_here
  python gtm/apollo_scraper.py

  python gtm/apollo_scraper.py --pages 5 --out leads.csv
  python gtm/apollo_scraper.py --geo "United States" --dry-run

Apollo free tier: 50 mobile + 100 export credits / month.
  Each page = 1 API call.  Each contact with email revealed = 1 export credit.
  Use --reveal-emails false to browse without spending export credits.

Requires:
  pip install requests
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from dataclasses import dataclass, field, fields
from datetime import datetime
from typing import Any

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

# ── Apollo API constants ──────────────────────────────────────────────────────

_APOLLO_BASE     = "https://api.apollo.io/v1"
_SEARCH_ENDPOINT = f"{_APOLLO_BASE}/mixed_people/search"
_PAGE_SIZE       = 25   # Apollo max per page on free tier
_RATE_LIMIT_WAIT = 1.2  # seconds between requests (free tier: 1 req/s)

# ── ICP (Ideal Customer Profile) filters ─────────────────────────────────────

_ICP_TITLES: list[str] = [
    "CTO",
    "CISO",
    "Chief Technology Officer",
    "Chief Information Security Officer",
    "IT Director",
    "Director of IT",
    "VP of Technology",
    "VP Technology",
    "Head of IT",
    "Founder",
    "Co-Founder",
    "Managing Director",
]

_ICP_INDUSTRIES: list[str] = [
    "Information Technology and Services",
    "Managed Service Provider",
    "Managed Services",
    "IT Services and IT Consulting",
    "Computer & Network Security",
    "Computer Networking",
]

_ICP_GEO_DEFAULT: list[str] = [
    "United States",
    "United Kingdom",
    "Israel",
    "Germany",
    "Netherlands",
    "Australia",
]

# Company size: focus on SMB MSPs (10-500 employees) — large enough to have
# multiple clients, small enough to move fast on procurement.
_ICP_EMPLOYEE_RANGES: list[str] = [
    "1,10",
    "11,20",
    "21,50",
    "51,100",
    "101,200",
    "201,500",
]


# ── Lead dataclass ────────────────────────────────────────────────────────────

@dataclass
class Lead:
    first_name:            str = ""
    last_name:             str = ""
    email:                 str = ""
    title:                 str = ""
    company:               str = ""
    company_size:          str = ""
    industry:              str = ""
    country:               str = ""
    city:                  str = ""
    linkedin_url:          str = ""
    company_website:       str = ""
    personalization:       str = ""   # pre-built first line for outreach
    apollo_id:             str = ""   # dedup key

    # CSV column order (exported to Instantly / Lemlist)
    @classmethod
    def csv_headers(cls) -> list[str]:
        return [f.name for f in fields(cls) if f.name != "apollo_id"]


# ── Personalization builder ───────────────────────────────────────────────────

def _build_personalization(person: dict[str, Any]) -> str:
    """
    Generate a one-line conversation-starter for the outreach email.

    Priority order:
      1. Most recent job change (signals growth / pain)
      2. Company size milestone
      3. Generic ICP-relevant opener
    """
    name        = person.get("first_name", "")
    company     = (person.get("organization") or {}).get("name", "")
    employee_ct = (person.get("organization") or {}).get("estimated_num_employees")
    title       = person.get("title", "")

    if employee_ct and employee_ct > 100:
        return (
            f"I saw {company} has grown to {employee_ct}+ people -- "
            f"at that scale, AI data exposure across your client base is probably something "
            f"you're already thinking about."
        )

    if "founder" in title.lower() or "co-founder" in title.lower():
        return (
            f"I came across {company} while researching MSPs building serious AI practices -- "
            f"wanted to reach out founder to founder."
        )

    if company:
        return (
            f"I was looking at {company} and noticed you're in the MSP space -- "
            f"wanted to share something specific to AI risk at your scale."
        )

    return (
        f"Quick question for you as someone running IT security at an MSP -- "
        f"do you currently have visibility into what your team sends to AI tools?"
    )


# ── Apollo API client ─────────────────────────────────────────────────────────

def _build_payload(
    page: int,
    geo: list[str],
    reveal_emails: bool,
) -> dict[str, Any]:
    return {
        "page":                    page,
        "per_page":                _PAGE_SIZE,
        "person_titles":           _ICP_TITLES,
        "organization_industry_tag_ids": [],   # resolved via keyword below
        "q_organization_keyword_tags":   _ICP_INDUSTRIES,
        "person_locations":        geo,
        "organization_num_employees_ranges": _ICP_EMPLOYEE_RANGES,
        "contact_email_status":    ["verified", "likely to engage"] if reveal_emails else [],
        "reveal_personal_emails":  False,   # business emails only
        "prospected_by_current_team": ["no"],  # exclude already-contacted
    }


def fetch_page(
    api_key: str,
    page: int,
    geo: list[str],
    reveal_emails: bool,
    dry_run: bool,
) -> tuple[list[dict[str, Any]], int]:
    """
    Fetch one page of people from Apollo.

    Returns (contacts_list, total_count).
    On dry_run, returns mock data so the pipeline can be tested without
    consuming API credits.
    """
    if dry_run:
        mock = {
            "first_name": "Jane",
            "last_name": f"Doe-{page}",
            "id": f"mock-{page}",
            "title": "CTO",
            "email": f"jane.doe.{page}@example-msp.com",
            "organization": {
                "name": f"Example MSP {page}",
                "estimated_num_employees": 45,
                "primary_domain": "example-msp.com",
            },
            "city": "Austin",
            "country": "United States",
            "linkedin_url": "https://linkedin.com/in/janedoe",
        }
        return [mock], 999   # pretend there are 999 results

    payload = _build_payload(page, geo, reveal_emails)
    headers = {
        "Content-Type":  "application/json",
        "Cache-Control": "no-cache",
        "X-Api-Key":     api_key,
    }

    resp = requests.post(
        _SEARCH_ENDPOINT,
        headers=headers,
        json=payload,
        timeout=30,
    )

    if resp.status_code == 429:
        print("  [rate-limit] Apollo returned 429 — sleeping 60s …", file=sys.stderr)
        time.sleep(60)
        return fetch_page(api_key, page, geo, reveal_emails, dry_run)

    if not resp.ok:
        print(
            f"  [error] Apollo API {resp.status_code}: {resp.text[:200]}",
            file=sys.stderr,
        )
        return [], 0

    data     = resp.json()
    contacts = data.get("people", data.get("contacts", []))
    total    = data.get("pagination", {}).get("total_entries", len(contacts))
    return contacts, total


def parse_contact(person: dict[str, Any]) -> Lead:
    org  = person.get("organization") or {}
    city = person.get("city") or ""

    return Lead(
        apollo_id      = person.get("id", ""),
        first_name     = person.get("first_name", ""),
        last_name      = person.get("last_name", ""),
        email          = person.get("email", ""),
        title          = person.get("title", ""),
        company        = org.get("name", ""),
        company_size   = str(org.get("estimated_num_employees", "")),
        industry       = org.get("industry", ""),
        country        = person.get("country", ""),
        city           = city,
        linkedin_url   = person.get("linkedin_url", ""),
        company_website= org.get("primary_domain", ""),
        personalization= _build_personalization(person),
    )


# ── CSV writer ────────────────────────────────────────────────────────────────

def write_csv(leads: list[Lead], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=Lead.csv_headers())
        writer.writeheader()
        for lead in leads:
            row = {k: getattr(lead, k) for k in Lead.csv_headers()}
            writer.writerow(row)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Scrape MSP decision-makers from Apollo.io and export to CSV."
    )
    parser.add_argument(
        "--pages", type=int, default=4,
        help="Number of pages to fetch (default: 4 = 100 leads). "
             "Free tier: use conservatively to preserve export credits.",
    )
    parser.add_argument(
        "--out", default="gtm/leads.csv",
        help="Output CSV path (default: gtm/leads.csv)",
    )
    parser.add_argument(
        "--geo", nargs="+", default=_ICP_GEO_DEFAULT,
        help="Countries to target (space-separated, quoted if multi-word).",
    )
    parser.add_argument(
        "--reveal-emails", action=argparse.BooleanOptionalAction, default=True,
        help="Reveal verified emails (uses export credits). "
             "Use --no-reveal-emails to browse without spending credits.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Run pipeline without calling Apollo (mock data). "
             "Useful for testing CSV output and personalization logic.",
    )
    parser.add_argument(
        "--min-email", action="store_true",
        help="Skip leads with no email (default: include all, mark email as empty).",
    )
    args = parser.parse_args()

    if not HAS_REQUESTS:
        print("ERROR: requests is required.  Run:  pip install requests", file=sys.stderr)
        sys.exit(2)

    api_key = os.environ.get("APOLLO_API_KEY", "")
    if not api_key and not args.dry_run:
        print(
            "ERROR: Set APOLLO_API_KEY environment variable.\n"
            "  export APOLLO_API_KEY=your_key_here\n"
            "  Get a key at https://app.apollo.io/settings/integrations/api",
            file=sys.stderr,
        )
        sys.exit(2)

    print(f"\nShadow Warden AI -- Lead Generation")
    print(f"Geo:        {', '.join(args.geo)}")
    print(f"Pages:      {args.pages}  ({args.pages * _PAGE_SIZE} leads max)")
    print(f"Emails:     {'reveal (costs credits)' if args.reveal_emails else 'browse only (free)'}")
    print(f"Output:     {args.out}")
    if args.dry_run:
        print("Mode:       DRY RUN (no API calls, mock data)")
    print("-" * 50)

    seen_ids:  set[str] = set()
    seen_emails: set[str] = set()
    leads:     list[Lead] = []
    total      = None

    for page in range(1, args.pages + 1):
        print(f"  Page {page}/{args.pages} ...", end=" ", flush=True)

        contacts, page_total = fetch_page(
            api_key, page, args.geo, args.reveal_emails, args.dry_run
        )

        if total is None:
            total = page_total
            print(f"  (Apollo reports ~{total} total matches)")

        if not contacts:
            print(f"  No contacts returned on page {page}. Stopping.")
            break

        new_on_page = 0
        for person in contacts:
            lead = parse_contact(person)

            # Dedup by Apollo ID
            if lead.apollo_id and lead.apollo_id in seen_ids:
                continue
            # Dedup by email (avoid loading the same contact twice under a diff ID)
            if lead.email and lead.email in seen_emails:
                continue
            # Optional: skip contacts without a verified email
            if args.min_email and not lead.email:
                continue

            seen_ids.add(lead.apollo_id)
            if lead.email:
                seen_emails.add(lead.email)

            leads.append(lead)
            new_on_page += 1

        print(f"  +{new_on_page} leads  (total: {len(leads)})")

        if page < args.pages:
            time.sleep(_RATE_LIMIT_WAIT)

    if not leads:
        print("\nNo leads collected. Check your API key and filters.")
        sys.exit(1)

    # Sort: verified email first, then alphabetical by company
    leads.sort(key=lambda l: (not bool(l.email), l.company.lower()))

    write_csv(leads, args.out)

    with_email    = sum(1 for l in leads if l.email)
    without_email = len(leads) - with_email

    print(f"\n  Saved {len(leads)} leads -> {args.out}")
    print(f"  With verified email: {with_email}")
    print(f"  Without email:       {without_email}")
    print(f"\n  Next steps:")
    print(f"  1. Open {args.out} and review / enrich top 20 manually")
    print(f"  2. Import to Instantly: Leads -> Import -> CSV")
    print(f"     Map: Email, First Name, Last Name, Company, Personalization")
    print("  3. Assign to campaign -> cold_outreach_sequence (Email 1)")
    print()


if __name__ == "__main__":
    main()
