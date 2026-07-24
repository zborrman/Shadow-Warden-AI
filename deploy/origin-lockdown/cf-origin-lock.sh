#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# cf-origin-lock.sh — restrict Docker-published 80/443 to Cloudflare source IPs.
#
# WHY THIS EXISTS (and why the "obvious" fixes don't work):
#   • Every WAF / rate-limit / Bot-Fight / skip rule in Cloudflare is edge-only.
#     A request sent straight to the origin IP bypasses ALL of it. Full(Strict)
#     TLS does not help — it only proves the origin holds a valid cert.
#   • ufw does NOT gate this. Docker publishes ports via its own iptables DNAT
#     that runs BEFORE ufw's INPUT chain, so ufw allow/deny has zero effect on
#     container-published ports. The only reliable hook is the DOCKER-USER chain
#     (evaluated before Docker's own FORWARD rules).
#   • Caddy client_auth (Authenticated Origin Pulls) does NOT work here either:
#     all vhosts share one multi-SAN cert and Caddy v2.11.4 silently drops
#     client_authentication when it consolidates >=2 same-cert connection
#     policies (`caddy adapt | grep -c client_authentication` == 0, config still
#     "valid"). See docs/cloudflare-waf.md.
#
# WHAT IT DOES: builds an ipset of Cloudflare's published ranges and inserts
# DOCKER-USER rules scoped to the public NIC — RETURN (allow) CF source on
# tcp 80,443 + udp 443 (HTTP/3), DROP everything else. Idempotent; fails CLOSED
# (never opens the origin) if the CF list can't be fetched and isn't cached.
#
# Recovery if it ever breaks ingress:
#   iptables -F DOCKER-USER; ip6tables -F DOCKER-USER
# SSH/22 is never touched by these rules.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# Public interface — auto-detect (route to the internet), override with CF_LOCK_IFACE.
IF="${CF_LOCK_IFACE:-$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'dev \K\S+' || echo eth0)}"
CACHE=/etc/cf-origin-lock
mkdir -p "$CACHE"

ipset create cf4 hash:net -exist
ipset create cf6 hash:net family inet6 -exist

# Fetch fresh ranges; keep last-known-good cache so a boot before DNS is ready
# still enforces (fail CLOSED) instead of opening the origin.
if curl -fsS --max-time 10 https://www.cloudflare.com/ips-v4 -o "$CACHE/v4.new" && [ -s "$CACHE/v4.new" ]; then mv "$CACHE/v4.new" "$CACHE/v4"; fi
if curl -fsS --max-time 10 https://www.cloudflare.com/ips-v6 -o "$CACHE/v6.new" && [ -s "$CACHE/v6.new" ]; then mv "$CACHE/v6.new" "$CACHE/v6"; fi
rm -f "$CACHE/v4.new" "$CACHE/v6.new"
[ -s "$CACHE/v4" ] && [ -s "$CACHE/v6" ] || { echo "cf-origin-lock: no CF list (fetch failed, no cache) — refusing to run"; exit 1; }

ipset flush cf4; while read -r c; do [ -n "$c" ] && ipset add cf4 "$c" -exist; done < "$CACHE/v4"
ipset flush cf6; while read -r c; do [ -n "$c" ] && ipset add cf6 "$c" -exist; done < "$CACHE/v6"

# Remove any prior cf-lock rules (idempotent re-run).
for ipt in iptables ip6tables; do
  while $ipt -S DOCKER-USER 2>/dev/null | grep -q 'cf-lock'; do
    r=$($ipt -S DOCKER-USER | grep -m1 'cf-lock' | sed 's/^-A/-D/'); $ipt $r
  done
done

# Insert allow-CF (RETURN) above drop-the-rest. -i "$IF" is REQUIRED — without it
# the DROP also kills internal cloudflared->proxy and inter-container traffic.
add() {  # $1 = iptables|ip6tables   $2 = ipset name
  $1 -I DOCKER-USER -i "$IF" -p tcp -m multiport --dports 80,443 -j DROP -m comment --comment cf-lock
  $1 -I DOCKER-USER -i "$IF" -p udp --dport 443 -j DROP -m comment --comment cf-lock
  $1 -I DOCKER-USER -i "$IF" -p tcp -m multiport --dports 80,443 -m set --match-set "$2" src -j RETURN -m comment --comment cf-lock
  $1 -I DOCKER-USER -i "$IF" -p udp --dport 443 -m set --match-set "$2" src -j RETURN -m comment --comment cf-lock
}
add iptables cf4
add ip6tables cf6

echo "cf-origin-lock applied on ${IF} ($(wc -l <"$CACHE/v4") v4 / $(wc -l <"$CACHE/v6") v6 ranges)"
