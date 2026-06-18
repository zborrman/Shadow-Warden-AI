"""
warden/whitelabel/config.py  (ENT-02)
──────────────────────────────────────
White-Label Mode — per-tenant custom domain, logo, and color scheme.

Config is stored in Redis under `whitelabel:{tenant_id}` and applied:
  - In the Caddy SNI routing (via template generation)
  - In Astro site build-time injection (custom CSS + logo swap)
  - In API responses: `X-Powered-By` header overridden when configured

Environment variables
---------------------
WHITELABEL_ENABLED=true   — global activation (default false)
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field

log = logging.getLogger("warden.whitelabel.config")

_ENABLED = os.getenv("WHITELABEL_ENABLED", "false").lower() == "true"
_in_proc: dict[str, dict] = {}


@dataclass
class WhitelabelConfig:
    tenant_id:    str
    domain:       str         = ""
    brand_name:   str         = "Shadow Warden AI"
    logo_url:     str         = "/logo.png"
    primary_color: str        = "#6366f1"
    secondary_color: str      = "#4f46e5"
    support_email: str        = ""
    hide_branding: bool       = False
    custom_css:   str         = ""
    custom_js:    str         = ""
    meta_tags:    dict        = field(default_factory=dict)


def _redis():
    try:
        import redis as rl  # noqa: PLC0415
        url = os.getenv("REDIS_URL", "redis://localhost:6379")
        if url.startswith("memory://"):
            return None
        r = rl.Redis.from_url(url, decode_responses=True)
        r.ping()
        return r
    except Exception:
        return None


def get_config(tenant_id: str) -> WhitelabelConfig:
    r = _redis()
    if r:
        raw = r.get(f"whitelabel:{tenant_id}")
        if raw:
            return WhitelabelConfig(**json.loads(raw))
    data = _in_proc.get(tenant_id)
    return WhitelabelConfig(**data) if data else WhitelabelConfig(tenant_id=tenant_id)


def save_config(cfg: WhitelabelConfig) -> None:
    data = asdict(cfg)
    r = _redis()
    if r:
        r.set(f"whitelabel:{cfg.tenant_id}", json.dumps(data))
    _in_proc[cfg.tenant_id] = data
    log.info("whitelabel: config saved — tenant=%s domain=%s", cfg.tenant_id, cfg.domain)


def delete_config(tenant_id: str) -> None:
    r = _redis()
    if r:
        r.delete(f"whitelabel:{tenant_id}")
    _in_proc.pop(tenant_id, None)


def render_css(cfg: WhitelabelConfig) -> str:
    """Generate CSS custom properties for the tenant's brand."""
    return (
        f":root {{\n"
        f"  --brand-primary: {cfg.primary_color};\n"
        f"  --brand-secondary: {cfg.secondary_color};\n"
        f"}}\n"
        + (cfg.custom_css or "")
    )


def caddy_vhost_snippet(cfg: WhitelabelConfig) -> str:
    """Generate Caddy v2 vhost snippet for the custom domain."""
    if not cfg.domain:
        return ""
    return (
        f"{cfg.domain} {{\n"
        f"  reverse_proxy warden:8001\n"
        f"  tls\n"
        f"  header X-Powered-By \"{cfg.brand_name}\"\n"
        f"}}\n"
    )
