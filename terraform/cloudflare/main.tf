terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
  required_version = ">= 1.5"
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

# ── Rate Limiting Rules ───────────────────────────────────────────────────────
# Matches the table in docs/cloudflare-waf.md

resource "cloudflare_ruleset" "rate_limits" {
  zone_id     = var.zone_id
  name        = "Shadow Warden Rate Limits"
  description = "Per-endpoint rate limits for Shadow Warden AI API"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules {
    action      = "block"
    description = "Staff agents throttle — 30 req/60 s"
    expression  = "(http.request.uri.path matches \"^/staff/agents/\")"
    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 30
      mitigation_timeout  = 60
    }
    enabled = true
  }

  rules {
    action      = "block"
    description = "Filter endpoint — 200 req/60 s"
    expression  = "(http.request.uri.path eq \"/filter\")"
    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 200
      mitigation_timeout  = 60
    }
    enabled = true
  }

  rules {
    action      = "block"
    description = "SOVA agent — 20 req/60 s"
    expression  = "(http.request.uri.path matches \"^/agent/\")"
    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 20
      mitigation_timeout  = 60
    }
    enabled = true
  }

  rules {
    action      = "block"
    description = "Auth endpoints — 10 req/60 s"
    expression  = "(http.request.uri.path matches \"^/auth/\")"
    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 10
      mitigation_timeout  = 300
    }
    enabled = true
  }

  rules {
    action      = "block"
    description = "Batch filter — 50 req/60 s"
    expression  = "(http.request.uri.path eq \"/filter/batch\")"
    ratelimit {
      characteristics     = ["ip.src"]
      period              = 60
      requests_per_period = 50
      mitigation_timeout  = 60
    }
    enabled = true
  }
}

# ── Custom WAF Rules ──────────────────────────────────────────────────────────
# Matches the 3 rules in docs/cloudflare-waf.md

resource "cloudflare_ruleset" "custom_waf" {
  zone_id     = var.zone_id
  name        = "Shadow Warden Custom WAF"
  description = "Custom WAF rules for Shadow Warden AI"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  rules {
    action      = "block"
    description = "Block staff routes missing X-API-Key"
    expression  = "(http.request.uri.path matches \"^/staff/\" and not any(http.request.headers[\"x-api-key\"][*] == http.request.headers[\"x-api-key\"][*]))"
    enabled     = true
  }

  rules {
    action      = "block"
    description = "Block suspiciously large bodies on agent endpoints (> 64 KB)"
    expression  = "(http.request.uri.path matches \"^/agent/\" and http.request.body.size gt 65536)"
    enabled     = true
  }

  rules {
    action      = "block"
    description = "Block sanctioned countries on financial endpoints"
    expression  = "(http.request.uri.path matches \"^/financial/\" and ip.geoip.country in {\"KP\" \"IR\" \"SY\" \"CU\"})"
    enabled     = true
  }
}
