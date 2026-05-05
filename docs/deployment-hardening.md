# Shadow Warden AI — Production Hardening Guide

**Version:** 4.11 · **Audience:** DevSecOps / Security engineers

> This guide assumes you have completed the basic deployment in `deployment-guide.md`.
> Apply every item in this guide **before** accepting production traffic.

---

## 1. Rotate All Default Credentials

### PostgreSQL

```bash
# Generate a strong password
DB_PASS=$(openssl rand -base64 32)

# Update in .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=${DB_PASS}/" .env

# Apply to running container
docker exec -it shadow-warden-postgres psql -U postgres \
  -c "ALTER USER postgres PASSWORD '${DB_PASS}';"
```

### Redis

```bash
REDIS_PASS=$(openssl rand -base64 32)
# Add to redis.conf:  requirepass <REDIS_PASS>
# Update REDIS_URL in .env:  redis://:${REDIS_PASS}@redis:6379/0
```

### MinIO

```bash
# Change root credentials via MinIO web console (port 9001) or:
docker exec -it shadow-warden-minio mc alias set local \
  http://localhost:9000 minioadmin minioadmin
docker exec -it shadow-warden-minio mc admin user add local \
  warden-svc $(openssl rand -base64 24)
```

### Warden API Key

```bash
# Generate a cryptographically-safe key
WARDEN_API_KEY=$(openssl rand -hex 32)
# Store in .env — never commit to git
echo "WARDEN_API_KEY=${WARDEN_API_KEY}" >> .env
```

---

## 2. TLS with Your Own Certificate

### Caddy (automatic ACME / Let's Encrypt)

```caddyfile
# docker/Caddyfile
api.your-domain.com {
    reverse_proxy warden:8001
}
```

Caddy auto-obtains and renews TLS. No manual cert management required.

### Bring Your Own Certificate

```caddyfile
api.your-domain.com {
    tls /certs/fullchain.pem /certs/privkey.pem
    reverse_proxy warden:8001
}
```

Mount the cert directory: `docker-compose.yml`:

```yaml
caddy:
  volumes:
    - ./certs:/certs:ro
```

---

## 3. Backup Strategy

### PostgreSQL — daily dump + offsite copy

```bash
#!/bin/bash
# /opt/shadow-warden/scripts/pg-backup.sh  (run via cron daily at 01:00)
set -euo pipefail
TS=$(date +%Y%m%d_%H%M%S)
DEST=/backups/postgres

docker exec shadow-warden-postgres pg_dumpall -U postgres \
  | gzip > "${DEST}/dump_${TS}.sql.gz"

# Keep last 14 days
find "${DEST}" -name "*.sql.gz" -mtime +14 -delete

# Offsite — replace with your S3/Backblaze/SFTP target
# aws s3 cp "${DEST}/dump_${TS}.sql.gz" s3://your-backup-bucket/postgres/
```

```bash
# Crontab entry:
0 1 * * * /opt/shadow-warden/scripts/pg-backup.sh >> /var/log/warden-backup.log 2>&1
```

### MinIO — mirror to offsite S3

```bash
# One-time setup: create mirror alias
mc alias set offsite https://s3.amazonaws.com ACCESS_KEY SECRET_KEY

# Continuous mirror (run as systemd service or cron every 6 hours)
mc mirror --watch local/warden-evidence offsite/your-backup-bucket/evidence/
mc mirror --watch local/warden-logs offsite/your-backup-bucket/logs/
```

### GDPR Note

The Evidence Vault (`warden-evidence`) contains anonymized attack metadata — **not** user content. Back it up for SOC 2 audit trail integrity.

---

## 4. Firewall — Minimal Exposure

Only ports 80 and 443 should be externally reachable:

```bash
# UFW (Ubuntu)
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp    # SSH — restrict to your IP only
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# Restrict SSH to your static IP:
ufw delete allow 22/tcp
ufw allow from YOUR_IP to any port 22
```

Docker Compose internal ports (5432, 6379, 9000, 9001, 3000, 8501) must **not** be bound to `0.0.0.0`. In `docker-compose.yml`, omit the host-port mapping or use `127.0.0.1:PORT:PORT`.

---

## 5. Container Security — Non-Root, Read-Only FS

All Warden containers already run as UID/GID 10001 (non-root). Enforce read-only root filesystem where possible:

```yaml
# docker-compose.yml additions per service
warden:
  read_only: true
  tmpfs:
    - /tmp
    - /warden/data   # overridden with a named volume below
  volumes:
    - warden-data:/warden/data
  security_opt:
    - no-new-privileges:true
```

---

## 6. seccomp Profiles

Apply Docker's default seccomp profile (blocks ~44 dangerous syscalls):

```yaml
# docker-compose.yml
warden:
  security_opt:
    - seccomp:unconfined   # REPLACE with path below for production
    # - seccomp:/etc/docker/seccomp/default.json
```

Download the hardened default profile:

```bash
curl -o /etc/docker/seccomp/warden-seccomp.json \
  https://raw.githubusercontent.com/moby/moby/master/profiles/seccomp/default.json
```

For Kubernetes (Helm values):

```yaml
# helm/shadow-warden/values.yaml
podSecurityContext:
  seccompProfile:
    type: RuntimeDefault   # or Localhost with a custom profile path
```

---

## 7. AppArmor Profiles

```bash
# Install AppArmor utilities
apt-get install -y apparmor-utils

# Use Docker's default AppArmor profile (docker-default)
# It is applied automatically when AppArmor is enabled on the host.
# Verify:
aa-status | grep docker-default
```

For custom restrictions on the warden service (e.g., deny write to /etc):

```bash
# /etc/apparmor.d/shadow-warden
#include <tunables/global>
profile shadow-warden flags=(attach_disconnected) {
  #include <abstractions/base>
  network,
  /proc/** r,
  /warden/data/** rw,
  /tmp/** rw,
  deny /etc/** w,
  deny /bin/** w,
}

# Load the profile:
apparmor_parser -r -W /etc/apparmor.d/shadow-warden
```

Docker Compose:

```yaml
warden:
  security_opt:
    - apparmor:shadow-warden
```

---

## 8. Secret Rotation — VAULT_MASTER_KEY

The `VAULT_MASTER_KEY` is a Fernet key used for PII vault encryption. Rotating it requires re-encrypting existing vault entries:

```python
# scripts/rotate_vault_key.py
from cryptography.fernet import Fernet, MultiFernet

old_key = Fernet(OLD_KEY)
new_key = Fernet(Fernet.generate_key())
multi   = MultiFernet([new_key, old_key])

# Re-encrypt all vault entries using multi.rotate(token)
# Then update VAULT_MASTER_KEY env var and restart warden
```

> **Never delete the old key until all tokens have been re-encrypted.**

---

## 9. GDPR Retention Verification

```bash
# Verify auto-retention is running (check ARQ worker logs):
docker logs shadow-warden-worker 2>&1 | grep "GDPR retention"

# Manual trigger:
curl -X DELETE https://api.your-domain.com/gdpr/purge/before/$(date -d '30 days ago' +%Y-%m-%d) \
  -H "X-API-Key: $WARDEN_API_KEY"

# Check current retention policy:
curl https://api.your-domain.com/gdpr/retention-policy \
  -H "X-API-Key: $WARDEN_API_KEY"
```

---

## 10. Verify SBOM and Image Signatures (after CI build)

```bash
# Verify image signature
cosign verify \
  --certificate-identity "https://github.com/zborrman/Shadow-Warden-AI/.github/workflows/ci.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/zborrman/shadow-warden:latest

# Inspect SBOM
cosign download sbom ghcr.io/zborrman/shadow-warden:latest | jq '.packages[].name'
```

---

## 11. Pre-Launch Checklist

```
[ ] All default passwords rotated (PG / Redis / MinIO / API key)
[ ] TLS active on port 443 (verify: curl -I https://api.your-domain.com/health)
[ ] Ports 5432, 6379, 9000 NOT exposed externally (verify: nmap your-server-ip)
[ ] UFW enabled, only 22/80/443 open
[ ] SSH key-only auth (PasswordAuthentication no in /etc/ssh/sshd_config)
[ ] non-root containers (verify: docker inspect --format='{{.Config.User}}' shadow-warden-warden)
[ ] no-new-privileges set
[ ] seccomp profile applied
[ ] GDPR retention cronjob active (check: docker logs shadow-warden-worker)
[ ] MinIO backup mirror running
[ ] PostgreSQL backup cron active
[ ] Grafana SLO alerts configured (import grafana/provisioning/alerting/warden_alerts.yml)
[ ] VAULT_MASTER_KEY is a valid Fernet key (warden logs "VAULT_MASTER_KEY validated" on startup)
[ ] WARDEN_API_KEY set (warden will refuse to start if unset and ALLOW_UNAUTHENTICATED != true)
[ ] Image signature verified with cosign
```
