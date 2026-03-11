"""
warden/onboarding.py
──────────────────────
SMB Tenant Onboarding Engine.

Automates the full lifecycle of adding a new SMB client to the gateway:
  1. Generates a tenant_id (URL-safe slug from company name)
  2. Creates a cryptographically secure API key
  3. Appends the key hash to the WARDEN_API_KEYS_PATH JSON file
  4. Sets a default billing quota based on the chosen plan
  5. Returns a ready-to-use setup kit (OPENAI_BASE_URL, .env template, curl test)

Plans
─────
  free  — 5 USD/month quota,     60 req/min
  pro   — 50 USD/month quota,   300 req/min
  msp   — unlimited quota (0),  600 req/min  (for MSP resellers)

Thread-safe: key file writes are protected by a threading.Lock.
Atomic writes: key file is written via tempfile + os.replace().
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("warden.onboarding")

_KEYS_PATH = Path(os.getenv("WARDEN_API_KEYS_PATH", "/warden/data/api_keys.json"))
_LOCK = threading.Lock()

PLANS: dict[str, dict] = {
    "free": {"quota_usd": 5.0,  "rate_limit": 60},
    "pro":  {"quota_usd": 50.0, "rate_limit": 300},
    "msp":  {"quota_usd": 0.0,  "rate_limit": 600},   # 0 = unlimited
}


# ── Setup kit returned to the caller ─────────────────────────────────────────

@dataclass
class TenantSetupKit:
    """
    Returned by OnboardingEngine.create_tenant().
    Contains everything a new SMB client needs to start using the gateway.

    api_key is shown ONCE — it is never stored in plaintext after this point.
    """
    tenant_id:       str
    api_key:         str      # raw key — displayed once, then gone
    plan:            str
    quota_usd:       float
    rate_limit:      int
    gateway_url:     str
    openai_base_url: str
    created_at:      str
    env_template:    str = field(init=False)
    curl_test:       str = field(init=False)

    def __post_init__(self) -> None:
        self.env_template = (
            f"# Shadow Warden AI — {self.tenant_id}\n"
            f"# Paste these into your .env file or shell profile\n"
            f"OPENAI_API_KEY={self.api_key}\n"
            f"OPENAI_BASE_URL={self.openai_base_url}\n"
            f"# All AI traffic now protected by Shadow Warden\n"
        )
        self.curl_test = (
            f'curl -s -X POST {self.gateway_url}/filter \\\n'
            f'  -H "Content-Type: application/json" \\\n'
            f'  -H "X-API-Key: {self.api_key}" \\\n'
            f'  -d \'{{"content": "Hello, test connection"}}\' \\\n'
            f'  | python -m json.tool'
        )

    def as_dict(self) -> dict:
        return {
            "tenant_id":       self.tenant_id,
            "api_key":         self.api_key,
            "plan":            self.plan,
            "quota_usd":       self.quota_usd,
            "rate_limit":      self.rate_limit,
            "gateway_url":     self.gateway_url,
            "openai_base_url": self.openai_base_url,
            "created_at":      self.created_at,
            "env_template":    self.env_template,
            "curl_test":       self.curl_test,
        }


# ── OnboardingEngine ──────────────────────────────────────────────────────────

class OnboardingEngine:
    """
    Creates and manages SMB tenant accounts on the gateway.

    Typical usage (main.py)::

        _onboarding = OnboardingEngine(gateway_url="https://ai.mycompany.com")

        kit = _onboarding.create_tenant(
            company_name  = "Acme Dental",
            contact_email = "admin@acmedental.com",
            plan          = "pro",
        )
        # kit.api_key — shown to the operator once, then discarded

        # MSP views all tenants
        tenants = _onboarding.list_tenants()

        # Rotate a compromised key
        new_key = _onboarding.rotate_key("acme-dental")
    """

    def __init__(
        self,
        gateway_url: str = "",
        keys_path:   Path | None = None,
    ) -> None:
        self._gateway_url = (
            gateway_url.rstrip("/") or
            os.getenv("GATEWAY_URL", "http://localhost:8001")
        )
        self._keys_path = keys_path or _KEYS_PATH
        self._keys_path.parent.mkdir(parents=True, exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────────

    def create_tenant(
        self,
        company_name:     str,
        contact_email:    str,
        plan:             str = "pro",
        telegram_chat_id: str | None = None,
        custom_quota_usd: float | None = None,
    ) -> TenantSetupKit:
        """
        Create a new SMB tenant.

        Raises
        ------
        ValueError
            If company_name is too short, plan is unknown, or tenant already exists.
        """
        company_name = company_name.strip()
        if len(company_name) < 2:
            raise ValueError("company_name must be at least 2 characters.")

        plan = plan.lower()
        if plan not in PLANS:
            raise ValueError(f"Unknown plan {plan!r}. Choose from: {list(PLANS)}")

        tenant_id = self._make_slug(company_name)
        if self._tenant_exists(tenant_id):
            raise ValueError(
                f"Tenant {tenant_id!r} already exists. "
                "Use rotate_key() to issue a new key."
            )

        api_key   = secrets.token_hex(32)   # 64-char hex, 256-bit entropy
        key_hash  = hashlib.sha256(api_key.encode()).hexdigest()
        plan_cfg  = PLANS[plan]
        quota_usd = custom_quota_usd if custom_quota_usd is not None else plan_cfg["quota_usd"]
        now       = datetime.now(UTC).isoformat()

        self._append_key({
            "key_hash":         key_hash,
            "tenant_id":        tenant_id,
            "label":            f"{company_name} ({plan})",
            "active":           True,
            "rate_limit":       plan_cfg["rate_limit"],
            "plan":             plan,
            "contact_email":    contact_email,
            "telegram_chat_id": telegram_chat_id,
            "quota_usd":        quota_usd,
            "created_at":       now,
            "rotated_at":       None,
        })

        log.info(
            "OnboardingEngine: created tenant=%s plan=%s quota=%.2f",
            tenant_id, plan, quota_usd,
        )

        return TenantSetupKit(
            tenant_id       = tenant_id,
            api_key         = api_key,
            plan            = plan,
            quota_usd       = quota_usd,
            rate_limit      = plan_cfg["rate_limit"],
            gateway_url     = self._gateway_url,
            openai_base_url = f"{self._gateway_url}/v1",
            created_at      = now,
        )

    def get_tenant(self, tenant_id: str) -> dict | None:
        """Return tenant metadata (without key_hash), or None if not found."""
        for entry in self._load_keys():
            if entry.get("tenant_id") == tenant_id:
                return {k: v for k, v in entry.items() if k != "key_hash"}
        return None

    def list_tenants(self) -> list[dict]:
        """Return all tenants (key hashes omitted)."""
        return [
            {k: v for k, v in e.items() if k != "key_hash"}
            for e in self._load_keys()
        ]

    def deactivate_tenant(self, tenant_id: str) -> bool:
        """Suspend a tenant's API key.  Returns True if found."""
        return self._set_active(tenant_id, active=False)

    def reactivate_tenant(self, tenant_id: str) -> bool:
        """Re-activate a suspended tenant.  Returns True if found."""
        return self._set_active(tenant_id, active=True)

    def rotate_key(self, tenant_id: str) -> str | None:
        """
        Issue a new API key for a tenant.

        Returns the new raw key (show once), or None if tenant not found.
        The old key is immediately invalidated.
        """
        with _LOCK:
            keys = self._load_keys()
            for entry in keys:
                if entry.get("tenant_id") == tenant_id:
                    new_key = secrets.token_hex(32)
                    entry["key_hash"]  = hashlib.sha256(new_key.encode()).hexdigest()
                    entry["rotated_at"] = datetime.now(UTC).isoformat()
                    self._save_keys(keys)
                    log.info("OnboardingEngine: rotated key for tenant=%s", tenant_id)
                    return new_key
        return None

    def update_telegram(self, tenant_id: str, chat_id: str | None) -> bool:
        """Store or clear a Telegram chat_id for a tenant.  Returns True if found."""
        with _LOCK:
            keys = self._load_keys()
            for entry in keys:
                if entry.get("tenant_id") == tenant_id:
                    entry["telegram_chat_id"] = chat_id
                    self._save_keys(keys)
                    return True
        return False

    def get_telegram_chat_id(self, tenant_id: str) -> str | None:
        """Return the Telegram chat_id for a tenant, or None."""
        entry = next(
            (e for e in self._load_keys() if e.get("tenant_id") == tenant_id),
            None,
        )
        return (entry or {}).get("telegram_chat_id")

    # ── Internal ───────────────────────────────────────────────────────────────

    @staticmethod
    def _make_slug(name: str) -> str:
        """Convert a company name to a URL-safe tenant_id slug (max 40 chars)."""
        slug = name.lower()
        slug = re.sub(r"[^a-z0-9]+", "-", slug)
        slug = slug.strip("-")[:40]
        return slug

    def _tenant_exists(self, tenant_id: str) -> bool:
        return any(e.get("tenant_id") == tenant_id for e in self._load_keys())

    def _load_keys(self) -> list[dict]:
        if not self._keys_path.exists():
            return []
        try:
            return json.loads(self._keys_path.read_text(encoding="utf-8")).get("keys", [])
        except Exception:
            log.warning("OnboardingEngine: could not parse %s", self._keys_path)
            return []

    def _save_keys(self, keys: list[dict]) -> None:
        """Atomic write — never leaves the file in a partial state."""
        tmp = self._keys_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"keys": keys}, indent=2), encoding="utf-8")
        tmp.replace(self._keys_path)

    def _append_key(self, entry: dict) -> None:
        with _LOCK:
            keys = self._load_keys()
            keys.append(entry)
            self._save_keys(keys)

    def _set_active(self, tenant_id: str, *, active: bool) -> bool:
        with _LOCK:
            keys = self._load_keys()
            for entry in keys:
                if entry.get("tenant_id") == tenant_id:
                    entry["active"] = active
                    self._save_keys(keys)
                    return True
        return False
