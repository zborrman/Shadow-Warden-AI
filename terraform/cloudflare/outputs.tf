output "rate_limits_ruleset_id" {
  description = "ID of the rate-limiting ruleset"
  value       = cloudflare_ruleset.rate_limits.id
}

output "custom_waf_ruleset_id" {
  description = "ID of the custom WAF ruleset"
  value       = cloudflare_ruleset.custom_waf.id
}
