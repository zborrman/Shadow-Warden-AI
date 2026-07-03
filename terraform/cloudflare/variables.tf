variable "cloudflare_api_token" {
  description = "Cloudflare API token scoped to Zone:Edit, Zone WAF:Edit for shadow-warden-ai.com"
  type        = string
  sensitive   = true
}

variable "zone_id" {
  description = "Cloudflare Zone ID for shadow-warden-ai.com (Settings → Overview → Zone ID)"
  type        = string
}

variable "account_id" {
  description = "Cloudflare Account ID (top-right corner of dashboard)"
  type        = string
}
