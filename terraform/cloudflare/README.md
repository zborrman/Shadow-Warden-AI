# Cloudflare WAF — Terraform

Codifies the WAF rules documented in `docs/cloudflare-waf.md`.

## Prerequisites

- Terraform >= 1.5
- Cloudflare API token with **Zone:Edit** + **Zone WAF:Edit** for `shadow-warden-ai.com`

## Usage

```bash
cd terraform/cloudflare

# First time
terraform init

# Preview changes (always do this before apply)
terraform plan \
  -var="cloudflare_api_token=$CLOUDFLARE_API_TOKEN" \
  -var="zone_id=$CLOUDFLARE_ZONE_ID" \
  -var="account_id=$CLOUDFLARE_ACCOUNT_ID"

# Apply (requires explicit confirmation)
terraform apply \
  -var="cloudflare_api_token=$CLOUDFLARE_API_TOKEN" \
  -var="zone_id=$CLOUDFLARE_ZONE_ID" \
  -var="account_id=$CLOUDFLARE_ACCOUNT_ID"
```

Or set env vars to avoid repeating flags:

```bash
export TF_VAR_cloudflare_api_token="$CLOUDFLARE_API_TOKEN"
export TF_VAR_zone_id="$CLOUDFLARE_ZONE_ID"
export TF_VAR_account_id="$CLOUDFLARE_ACCOUNT_ID"
terraform plan && terraform apply
```

## What this manages

| Resource | Description |
|----------|-------------|
| `cloudflare_ruleset.rate_limits` | 5 rate-limit rules (staff/filter/agent/auth/batch) |
| `cloudflare_ruleset.custom_waf` | 3 custom WAF rules (API key, body size, geo-block) |

## Not managed here

- OWASP Core Ruleset (enable via Dashboard → Security → WAF → Managed Rules)
- Super Bot Fight Mode (enable via Dashboard → Security → Bots)
- DNS / SSL settings (managed via Caddy + Cloudflare dashboard)
- Preflight Worker (deployed via `cloudflare/preflight-worker/` + CI)
