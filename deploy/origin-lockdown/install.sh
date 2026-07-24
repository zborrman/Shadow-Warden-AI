#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# install.sh — install + activate the Cloudflare-only origin lockdown.
# Idempotent. Run as root on the VPS (called by deploy/hetzner.sh, or by hand):
#   sudo bash deploy/origin-lockdown/install.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail
[[ $EUID -ne 0 ]] && { echo "install.sh: must run as root"; exit 1; }

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ipset is required by cf-origin-lock.sh
if ! command -v ipset &>/dev/null; then
  echo "installing ipset …"
  apt-get update -qq && apt-get install -y ipset
fi

install -m 0755 "$HERE/cf-origin-lock.sh"      /usr/local/sbin/cf-origin-lock.sh
install -m 0644 "$HERE/cf-origin-lock.service" /etc/systemd/system/cf-origin-lock.service

systemctl daemon-reload
systemctl enable --now cf-origin-lock.service

echo "── cf-origin-lock status ──"
systemctl is-active cf-origin-lock.service
iptables -L DOCKER-USER -n | grep -c cf-lock | sed 's/^/DOCKER-USER cf-lock rules: /'
echo "Done. Verify from OUTSIDE: a direct hit to the origin IP on :80/:443 should"
echo "time out, while the Cloudflare path stays 200. Recovery: iptables -F DOCKER-USER"
