# Origin lockdown — only Cloudflare may reach the origin

Every WAF / rate-limit / Bot-Fight / skip rule in Cloudflare is **edge-only**. A
request sent straight to the origin IP (`91.98.234.160`) bypasses all of it. This
directory pins the control that closes that hole, so a server rebuild or re-run of
`deploy/hetzner.sh` can't silently reopen it.

## What's here

| File | Purpose |
|------|---------|
| `cf-origin-lock.sh` | Builds an ipset of Cloudflare ranges, inserts `DOCKER-USER` rules scoped to the public NIC: allow CF source on tcp 80,443 + udp 443, drop the rest. Fails **closed**. |
| `cf-origin-lock.service` | systemd oneshot that reapplies the rules after Docker on every boot (a reboot clears iptables). |
| `install.sh` | Installs both, enables + starts the service. Idempotent. |

## Install / re-apply

```bash
sudo bash deploy/origin-lockdown/install.sh
```

Override the public interface if auto-detection is wrong:

```bash
CF_LOCK_IFACE=ens3 sudo bash deploy/origin-lockdown/install.sh   # affects the running script; edit the unit's Environment= to persist
```

## Verify (from OUTSIDE the box)

```bash
# direct-to-origin — must TIME OUT
curl -sS -k --resolve api.shadow-warden-ai.com:443:91.98.234.160 --max-time 12 \
  -o /dev/null -w "%{http_code}\n" https://api.shadow-warden-ai.com/health
# via Cloudflare — must be 200
curl -sS -o /dev/null -w "%{http_code}\n" https://api.shadow-warden-ai.com/health
```

## Refresh Cloudflare ranges

`systemctl restart cf-origin-lock` (or re-run the script). Consider a weekly
`systemd` timer so a Cloudflare range change can't silently break the edge path.

## Why not the "obvious" approaches

- **ufw** doesn't gate Docker-published ports — Docker's iptables DNAT runs before
  ufw's `INPUT` chain. `DOCKER-USER` is the only reliable hook.
- **Caddy `client_auth` (Authenticated Origin Pulls)** silently produces no
  `client_authentication` on Caddy v2.11.4 when ≥2 vhosts share one cert (policy
  consolidation drops it) — it *looks* enforced but isn't. See
  `docs/cloudflare-waf.md`.

## Recovery

If a bad rule ever blocks legitimate ingress:

```bash
iptables -F DOCKER-USER; ip6tables -F DOCKER-USER   # restores open access; SSH is untouched
```
