#!/usr/bin/env python3
"""
gtm/warmup_validator.py
━━━━━━━━━━━━━━━━━━━━━━
Email warm-up readiness validator for shadow-warden-ai.com.

Checks (in order):
  1. MX   — exactly 5 Google mail servers at correct priorities
  2. SPF  — TXT record contains v=spf1 include:_spf.google.com
  3. DMARC — _dmarc.<domain> contains v=DMARC1 with a policy tag
  4. DKIM  — google._domainkey.<domain> has a public key record
  5. DNSBL — domain / sending IP not listed on major spam blacklists

Usage:
  python gtm/warmup_validator.py
  python gtm/warmup_validator.py --domain shadow-warden-ai.com
  python gtm/warmup_validator.py --domain shadow-warden-ai.com --ip 1.2.3.4
  python gtm/warmup_validator.py --json          # machine-readable output

Requires:
  pip install dnspython
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from typing import Any

try:
    import dns.exception
    import dns.resolver
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


# ── Expected Google MX records ────────────────────────────────────────────────

_GOOGLE_MX: list[tuple[int, str]] = [
    (1,  "aspmx.l.google.com."),
    (5,  "alt1.aspmx.l.google.com."),
    (5,  "alt2.aspmx.l.google.com."),
    (10, "alt3.aspmx.l.google.com."),
    (10, "alt4.aspmx.l.google.com."),
]

# ── DNSBL zones to check (domain-based and IP-based) ─────────────────────────

_DNSBL_ZONES: list[tuple[str, str]] = [
    ("zen.spamhaus.org",          "Spamhaus ZEN (SBL+XBL+PBL)"),
    ("bl.spamcop.net",            "SpamCop"),
    ("dnsbl.sorbs.net",           "SORBS"),
    ("spam.dnsbl.sorbs.net",      "SORBS Spam"),
    ("b.barracudacentral.org",    "Barracuda"),
]


# ── Result dataclass ──────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name:    str
    passed:  bool
    detail:  str
    records: list[str] = field(default_factory=list)


# ── DNS helpers ───────────────────────────────────────────────────────────────

def _resolve(qname: str, rdtype: str, timeout: float = 5.0) -> list[Any]:
    """Return a list of rdata objects or [] on NXDOMAIN / timeout."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    try:
        return list(resolver.resolve(qname, rdtype))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout):
        return []


# ── Individual checks ─────────────────────────────────────────────────────────

def check_mx(domain: str) -> CheckResult:
    """Verify the 5 Google MX records are present with correct priorities."""
    records = _resolve(domain, "MX")
    if not records:
        return CheckResult("MX Records", False, "No MX records found.")

    found: list[tuple[int, str]] = sorted(
        [(r.preference, str(r.exchange).lower()) for r in records]
    )
    expected = sorted([(p, h) for p, h in _GOOGLE_MX])

    passed  = found == expected
    lines   = [f"  {pref:>3}  {host}" for pref, host in found]
    detail  = (
        "All 5 Google MX servers present at correct priorities."
        if passed else
        f"Expected {len(expected)} records, found {len(found)}. "
        "Verify all 5 Google MX records are added in Cloudflare."
    )
    return CheckResult("MX Records", passed, detail, lines)


def check_spf(domain: str) -> CheckResult:
    """Verify SPF TXT record includes Google's sending range."""
    records = _resolve(domain, "TXT")
    spf_records = [
        str(r).strip('"')
        for rdata in records
        for r in rdata.strings
        if str(r).startswith("v=spf1")
    ]

    if not spf_records:
        return CheckResult(
            "SPF Record", False,
            "No SPF (v=spf1) TXT record found. "
            'Add:  v=spf1 include:_spf.google.com ~all',
        )

    spf = spf_records[0]
    has_google  = "include:_spf.google.com" in spf
    has_all     = "~all" in spf or "-all" in spf or "?all" in spf

    passed = has_google and has_all
    detail = (
        "SPF includes _spf.google.com with a valid 'all' policy."
        if passed else
        (
            "SPF missing 'include:_spf.google.com'."
            if not has_google else
            "SPF has no 'all' qualifier (~all / -all)."
        )
    )
    return CheckResult("SPF Record", passed, detail, [f"  {spf}"])


def check_dmarc(domain: str) -> CheckResult:
    """Verify _dmarc.<domain> has a v=DMARC1 record with a policy tag."""
    qname   = f"_dmarc.{domain}"
    records = _resolve(qname, "TXT")
    dmarc_records = [
        str(r).strip('"')
        for rdata in records
        for r in rdata.strings
        if "v=DMARC1" in str(r)
    ]

    if not dmarc_records:
        return CheckResult(
            "DMARC Record", False,
            f"No DMARC record at {qname}. "
            'Add TXT:  v=DMARC1; p=none; rua=mailto:val@shadow-warden-ai.com',
        )

    dmarc = dmarc_records[0]
    policy_map = {"p=reject": "reject", "p=quarantine": "quarantine", "p=none": "none"}
    policy     = next((v for k, v in policy_map.items() if k in dmarc), None)

    passed = policy is not None
    detail = (
        f"DMARC present. Policy: {policy}."
        + ("  ⚠  Consider upgrading to p=quarantine or p=reject once domain is warmed."
           if policy == "none" else "")
        if passed else
        f"DMARC record found but no valid p= tag: {dmarc}"
    )
    return CheckResult("DMARC Record", passed, detail, [f"  {dmarc}"])


def check_dkim(domain: str) -> CheckResult:
    """Verify Google DKIM public key record exists (selector: google)."""
    qname   = f"google._domainkey.{domain}"
    records = _resolve(qname, "TXT")
    dkim_records = [
        str(r).strip('"')
        for rdata in records
        for r in rdata.strings
        if "v=DKIM1" in str(r) or "p=" in str(r)
    ]

    if not dkim_records:
        return CheckResult(
            "DKIM Record", False,
            f"No DKIM key at {qname}. "
            "In Google Workspace Admin -> Apps -> Gmail -> Authenticate email, "
            "generate a key and add the provided TXT record to Cloudflare.",
        )

    dkim = dkim_records[0]
    has_key = "p=" in dkim and not dkim.rstrip().endswith("p=")
    passed  = has_key
    detail  = (
        f"DKIM public key present at {qname}."
        if passed else
        f"DKIM record found but public key (p=) appears empty or revoked: {dkim[:60]}..."
    )
    # Truncate key material for display — never log full key
    display = dkim[:80] + "..." if len(dkim) > 80 else dkim
    return CheckResult("DKIM Record", passed, detail, [f"  {display}"])


def _reverse_ip(ip: str) -> str:
    """Convert 1.2.3.4 -> 4.3.2.1"""
    return ".".join(reversed(ip.split(".")))


def check_dnsbl(domain: str, sending_ip: str | None = None) -> CheckResult:
    """
    Query major DNSBL zones.

    Checks the sending IP if provided; otherwise falls back to resolving the
    domain's A record and checking that IP.
    """
    # Resolve IP to check
    ip = sending_ip
    if not ip:
        a_records = _resolve(domain, "A")
        ip = str(a_records[0]) if a_records else None

    if not ip:
        return CheckResult(
            "DNSBL / Blacklist", False,
            f"Could not determine IP for {domain} — pass --ip <address> to check manually.",
        )

    rev = _reverse_ip(ip)
    listings: list[str] = []
    checked:  list[str] = []

    for zone, label in _DNSBL_ZONES:
        query = f"{rev}.{zone}"
        result = _resolve(query, "A")
        status = "LISTED" if result else "clean"
        checked.append(f"  {label:<35} {status}")
        if result:
            listings.append(label)

    passed = len(listings) == 0
    detail = (
        f"IP {ip} not listed on any of {len(_DNSBL_ZONES)} checked blacklists."
        if passed else
        f"IP {ip} is LISTED on {len(listings)} blacklist(s): {', '.join(listings)}. "
        "Submit delisting requests before sending any outreach."
    )
    return CheckResult("DNSBL / Blacklist", passed, detail, checked)


# ── Report renderer ───────────────────────────────────────────────────────────

_GREEN = "\033[92m"
_RED   = "\033[91m"
_YELLOW = "\033[93m"
_BOLD  = "\033[1m"
_RESET = "\033[0m"

def _icon(passed: bool) -> str:
    return f"{_GREEN}+{_RESET}" if passed else f"{_RED}x{_RESET}"


def render_text(domain: str, results: list[CheckResult]) -> None:
    print(f"\n{_BOLD}Shadow Warden AI — Email Warm-up Readiness Report{_RESET}")
    print(f"Domain: {_BOLD}{domain}{_RESET}")
    print("-" * 58)

    for r in results:
        status = f"{_GREEN}PASS{_RESET}" if r.passed else f"{_RED}FAIL{_RESET}"
        print(f"\n  {_icon(r.passed)}  {_BOLD}{r.name}{_RESET}  [{status}]")
        print(f"     {r.detail}")
        for line in r.records:
            print(f"     {_YELLOW}{line.strip()}{_RESET}")

    print("\n" + "-" * 58)
    passed_count = sum(1 for r in results if r.passed)
    total        = len(results)

    if passed_count == total:
        print(f"\n  {_GREEN}{_BOLD}All {total} checks passed.{_RESET}")
        print("  Your domain is ready for warm-up.")
        print("  -> Add val@shadow-warden-ai.com to Instantly.ai / Lemlist.")
        print("  -> Start at 2 emails/day, +2 each day, cap at 35/day.")
    else:
        failed = total - passed_count
        print(f"\n  {_RED}{_BOLD}{failed} check(s) failed.{_RESET}  Fix them before starting warm-up.")
        print("  Re-run this script after updating DNS (allow up to 5 min for propagation).")
    print()


def render_json(domain: str, results: list[CheckResult]) -> None:
    output = {
        "domain":       domain,
        "ready":        all(r.passed for r in results),
        "passed":       sum(1 for r in results if r.passed),
        "total":        len(results),
        "checks":       [asdict(r) for r in results],
    }
    print(json.dumps(output, indent=2))


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Validate email DNS configuration before warm-up."
    )
    parser.add_argument(
        "--domain", default="shadow-warden-ai.com",
        help="Domain to validate (default: shadow-warden-ai.com)",
    )
    parser.add_argument(
        "--ip", default=None,
        help="Sending IP address to check against DNSBL (auto-detected if omitted)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output results as JSON (for CI / monitoring integration)",
    )
    args = parser.parse_args()

    if not HAS_DNSPYTHON:
        print("ERROR: dnspython is required.  Run:  pip install dnspython", file=sys.stderr)
        sys.exit(2)

    domain  = args.domain
    results = [
        check_mx(domain),
        check_spf(domain),
        check_dmarc(domain),
        check_dkim(domain),
        check_dnsbl(domain, sending_ip=args.ip),
    ]

    if args.json:
        render_json(domain, results)
    else:
        render_text(domain, results)

    # Exit 1 if any check failed (useful in CI pipelines)
    if not all(r.passed for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
