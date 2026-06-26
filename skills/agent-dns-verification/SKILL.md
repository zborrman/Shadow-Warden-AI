# Skill: Agent DNS Verification (ANS / DID-over-DNS)

**Purpose:** Verify incoming agent DIDs against authoritative DNS records before the Brand Agent accepts a proposal. Catches spoofed DIDs and mismatch between claimed identity and actual origin without an external registry dependency.

---

## When to invoke

Invoke this skill when:
- A new agent registers via `POST /marketplace/register`
- A seller receives a first proposal from an unknown `buyer_agent_id`
- `BrandAgentFilter` TrustRank gate returns score below `BRAND_AGENT_MIN_TRUST`
- The incoming DID format is `did:web:` or `did:shadow:` with a domain component

---

## Protocol: DID-over-DNS verification

### Step 1 — Extract domain from DID

| DID format | Domain extraction |
|------------|-------------------|
| `did:web:example.com` | `example.com` |
| `did:web:example.com:marketplace:agent1` | `example.com` |
| `did:shadow:<hash>` + `X-Agent-Domain` header | Use header value |

If no domain is resolvable, skip DNS check and fall back to TrustRank.

### Step 2 — Query DNS TXT record

```
_agent-did.example.com  TXT  "did=did:web:example.com agent_id=did:shadow:abc123"
```

Resolution via Python:
```python
import dns.resolver  # dnspython
records = dns.resolver.resolve(f"_agent-did.{domain}", "TXT")
for r in records:
    txt = r.to_text().strip('"')
    if f"agent_id={claimed_did}" in txt or f"did={claimed_did}" in txt:
        return True  # verified
return False  # no match → flag for TrustRank review
```

### Step 3 — SRV record (optional, high-assurance)

```
_agent-mep._tcp.example.com  SRV  0 5 443 api.example.com
```

If SRV present: verify HTTPS endpoint returns `/.well-known/agent.json` with matching `did` field and valid Ed25519 signature over a nonce. This is the full BOTCHA-equivalent handshake.

### Step 4 — Result handling

| Result | Action |
|--------|--------|
| DNS match ✅ | Record `dns_verified=True` in `marketplace_agents` table; TrustRank boost +0.1 |
| DNS mismatch ❌ | Log warning; reject if `BRAND_AGENT_STRICT_DNS=true`, else flag for manual review |
| No DNS record | Log info; continue with TrustRank-only scoring (default) |
| DNS timeout | Fail-open; log warning; continue |

---

## Implementation hook

Add to `warden/marketplace/brand_agent.py` → `BrandAgentFilter.check()`:
```python
async def _dns_verify(self, agent_id: str, domain: str | None) -> bool:
    if not domain:
        return True  # no domain to check — skip (fail-open)
    try:
        import dns.resolver
        records = dns.resolver.resolve(f"_agent-did.{domain}", "TXT", lifetime=3.0)
        for r in records:
            if agent_id in r.to_text():
                return True
        return False
    except Exception as exc:
        log.warning("dns_verify fail-open domain=%s: %s", domain, exc)
        return True  # fail-open
```

---

## Env vars

| Var | Default | Effect |
|-----|---------|--------|
| `BRAND_AGENT_STRICT_DNS` | `false` | `true` = reject unverified DIDs; `false` = flag only |
| `BRAND_AGENT_DNS_TIMEOUT` | `3.0` | DNS query timeout (seconds) |

## Dependencies

```
pip install dnspython
```
Already in the `[dev]` extras if you use `pip install -e ".[dev]"`. Add to `warden/requirements.txt` for production.
