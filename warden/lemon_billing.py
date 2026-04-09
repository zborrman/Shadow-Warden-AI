"""
warden/lemon_billing.py
────────────────────────
Lemon Squeezy subscription management for Shadow Warden AI.

Plans (monthly subscriptions)
──────────────────────────────
  starter    — 1 000 req/month,  $0/month  (default, no LS required)
  individual — 5 000 req/month,  $5/month
  pro        — 50 000 req/month, $49/month
  enterprise — Unlimited,        $199/month

Lifecycle
─────────
  1. Client calls POST /subscription/checkout → gets a Lemon Squeezy checkout URL
  2. After payment, LS fires subscription_created webhook
  3. Webhook handler upserts the subscription row for that tenant
  4. Every /filter call reads get_quota(tenant_id) from this store

Environment variables
─────────────────────
  LEMONSQUEEZY_API_KEY          — API key (Lemon Squeezy dashboard → API)
  LEMONSQUEEZY_STORE_ID         — Store ID from LS dashboard
  LEMONSQUEEZY_WEBHOOK_SECRET   — Webhook signing secret (LS dashboard → Webhooks)
  LEMONSQUEEZY_VARIANT_INDIVIDUAL — variant_id for Individual plan ($5/mo)
  LEMONSQUEEZY_VARIANT_PRO        — variant_id for Pro plan ($49/mo)
  LEMONSQUEEZY_VARIANT_ENTERPRISE — variant_id for Enterprise plan ($199/mo)
  LEMONSQUEEZY_DB_PATH          — SQLite path (default /warden/data/lemon.db)

Thread-safe: all writes protected by threading.Lock + WAL journal mode.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import threading
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("warden.lemon_billing")

_LS_API_KEY          = os.getenv("LEMONSQUEEZY_API_KEY", "")
_LS_STORE_ID         = os.getenv("LEMONSQUEEZY_STORE_ID", "")
_LS_WEBHOOK_SECRET   = os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET", "")
_LS_VARIANT_INDIVIDUAL = os.getenv("LEMONSQUEEZY_VARIANT_INDIVIDUAL", "")
_LS_VARIANT_PRO        = os.getenv("LEMONSQUEEZY_VARIANT_PRO", "")
_LS_VARIANT_ENTERPRISE = os.getenv("LEMONSQUEEZY_VARIANT_ENTERPRISE", "")

_LS_API_BASE = "https://api.lemonsqueezy.com/v1"


def _db_path() -> Path:
    """Resolved lazily so test env vars set after import are respected."""
    return Path(os.getenv("LEMONSQUEEZY_DB_PATH", "/warden/data/lemon.db"))


# ── Plan definitions ──────────────────────────────────────────────────────────

PLAN_QUOTAS: dict[str, int | None] = {
    "starter":    1_000,
    "individual": 5_000,
    "pro":        50_000,
    "enterprise": None,      # unlimited
}

# Backwards-compat aliases used by existing quota checks
PLAN_QUOTAS["free"] = PLAN_QUOTAS["starter"]
PLAN_QUOTAS["msp"]  = PLAN_QUOTAS["enterprise"]


def _variant_to_plan(variant_id: str) -> str:
    mapping = {
        _LS_VARIANT_INDIVIDUAL: "individual",
        _LS_VARIANT_PRO:        "pro",
        _LS_VARIANT_ENTERPRISE: "enterprise",
    }
    return mapping.get(variant_id, "individual")


# ── Lemon Squeezy REST helper ─────────────────────────────────────────────────

def _ls_request(method: str, path: str, body: dict | None = None) -> dict:
    url  = f"{_LS_API_BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data,
        headers={
            "Authorization": f"Bearer {_LS_API_KEY}",
            "Content-Type":  "application/vnd.api+json",
            "Accept":        "application/vnd.api+json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        raise RuntimeError(f"Lemon Squeezy API {exc.code}: {body_text}") from exc


# ── LemonBilling ──────────────────────────────────────────────────────────────

class LemonBilling:
    """Manages Lemon Squeezy subscriptions and plan state per tenant."""

    def __init__(self, db_path: Path | None = None) -> None:
        db_path = db_path or _db_path()
        self._enabled = bool(_LS_API_KEY)
        self._path    = db_path
        self._lock    = threading.Lock()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn    = self._open()
        self._init_schema()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript("""
                CREATE TABLE IF NOT EXISTS subscriptions (
                    tenant_id       TEXT PRIMARY KEY,
                    ls_customer_id  TEXT,
                    ls_sub_id       TEXT,
                    plan            TEXT NOT NULL DEFAULT 'starter',
                    status          TEXT NOT NULL DEFAULT 'active',
                    renews_at       TEXT,
                    updated_at      TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_subs_ls_sub
                    ON subscriptions(ls_sub_id);
            """)
            self._conn.commit()

    # ── Plan / quota queries ──────────────────────────────────────────────────

    def get_plan(self, tenant_id: str) -> str:
        row = self._conn.execute(
            "SELECT plan, status FROM subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            return "starter"
        if row["status"] not in ("active", "on_trial"):
            return "starter"
        return row["plan"]

    def get_quota(self, tenant_id: str) -> int | None:
        return PLAN_QUOTAS.get(self.get_plan(tenant_id), PLAN_QUOTAS["starter"])

    def get_status(self, tenant_id: str) -> dict:
        row = self._conn.execute(
            "SELECT * FROM subscriptions WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        plan = self.get_plan(tenant_id)
        return {
            "tenant_id":   tenant_id,
            "plan":        plan,
            "quota":       PLAN_QUOTAS.get(plan),
            "status":      row["status"] if row else "starter",
            "renews_at":   row["renews_at"] if row else None,
            "customer_id": row["ls_customer_id"] if row else None,
        }

    # ── Checkout ──────────────────────────────────────────────────────────────

    def create_checkout_session(
        self,
        tenant_id:      str,
        plan:           str,
        success_url:    str,
        cancel_url:     str,
        customer_email: str | None = None,
    ) -> str:
        """Create a Lemon Squeezy checkout and return the hosted URL."""
        if not self._enabled:
            raise RuntimeError("Lemon Squeezy not configured (LEMONSQUEEZY_API_KEY missing).")

        variant_map = {
            "individual": _LS_VARIANT_INDIVIDUAL,
            "pro":        _LS_VARIANT_PRO,
            "enterprise": _LS_VARIANT_ENTERPRISE,
            # backwards-compat aliases
            "msp":        _LS_VARIANT_ENTERPRISE,
        }
        variant_id = variant_map.get(plan, "")
        if not variant_id:
            raise ValueError(
                f"Invalid plan {plan!r} or variant not configured. "
                "Set LEMONSQUEEZY_VARIANT_<PLAN> env var."
            )

        body: dict = {
            "data": {
                "type": "checkouts",
                "attributes": {
                    "checkout_options": {
                        "embed": False,
                    },
                    "checkout_data": {
                        "custom": {"tenant_id": tenant_id},
                    },
                    "product_options": {
                        "redirect_url":        success_url,
                    },
                },
                "relationships": {
                    "store": {
                        "data": {"type": "stores", "id": _LS_STORE_ID}
                    },
                    "variant": {
                        "data": {"type": "variants", "id": variant_id}
                    },
                },
            }
        }
        if customer_email:
            body["data"]["attributes"]["checkout_data"]["email"] = customer_email

        resp = _ls_request("POST", "/checkouts", body)
        url  = (resp.get("data") or {}).get("attributes", {}).get("url", "")
        if not url:
            raise RuntimeError("Lemon Squeezy did not return a checkout URL.")

        log.info("LemonSqueezy: checkout created tenant=%s plan=%s.", tenant_id, plan)
        return url

    # ── Customer Portal ───────────────────────────────────────────────────────

    def get_portal_url(self, tenant_id: str) -> str:
        """
        Return a Lemon Squeezy customer portal URL for self-serve plan management.
        """
        row = self._conn.execute(
            "SELECT ls_customer_id FROM subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()

        if self._enabled and row and row["ls_customer_id"]:
            # Lemon Squeezy customer portal is at my.lemonsqueezy.com
            return f"https://app.lemonsqueezy.com/my-orders"

        return "https://app.lemonsqueezy.com/my-orders"

    # ── Webhook handler ───────────────────────────────────────────────────────

    def handle_webhook(self, payload: bytes, signature_header: str) -> str:
        """
        Validate and process a Lemon Squeezy webhook event.

        X-Signature header: HMAC-SHA256 hex digest of the raw payload.
        Returns the event_name string.
        Raises ValueError on invalid signature.
        """
        if _LS_WEBHOOK_SECRET and signature_header:
            expected = hmac.new(
                _LS_WEBHOOK_SECRET.encode(),
                payload,
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, signature_header):
                raise ValueError("Invalid Lemon Squeezy webhook signature.")

        event      = json.loads(payload)
        meta       = event.get("meta", {})
        event_name = meta.get("event_name", "")
        data       = event.get("data", {})

        if event_name in ("subscription_created", "subscription_updated", "subscription_resumed"):
            self._on_subscription_active(data, meta)
        elif event_name in ("subscription_cancelled", "subscription_expired"):
            self._on_subscription_cancelled(data)
        elif event_name == "subscription_payment_failed":
            sub_id = str(data.get("id", ""))
            if sub_id:
                self._set_status_by_sub(sub_id, "past_due")
        elif event_name == "order_created":
            # One-time orders (if used) — treat same as subscription activation
            self._on_order_created(data, meta)

        log.info("LemonSqueezy webhook: %s processed.", event_name)
        return event_name

    # ── Webhook sub-handlers ──────────────────────────────────────────────────

    def _on_subscription_active(self, data: dict, meta: dict) -> None:
        attrs       = data.get("attributes", {})
        custom      = meta.get("custom_data") or {}
        tenant_id   = custom.get("tenant_id", "")
        if not tenant_id:
            log.warning("LemonSqueezy: webhook missing tenant_id in custom_data.")
            return
        sub_id      = str(data.get("id", ""))
        customer_id = str(attrs.get("customer_id", ""))
        variant_id  = str(attrs.get("variant_id", ""))
        plan        = _variant_to_plan(variant_id)
        status      = attrs.get("status", "active")
        renews_at   = attrs.get("renews_at")
        self._upsert(tenant_id, customer_id, sub_id, plan, status, renews_at)
        log.info("LemonSqueezy: tenant %s activated plan=%s.", tenant_id, plan)

    def _on_subscription_cancelled(self, data: dict) -> None:
        sub_id = str(data.get("id", ""))
        with self._lock:
            self._conn.execute(
                "UPDATE subscriptions SET plan='starter', status='cancelled', updated_at=?"
                " WHERE ls_sub_id=?",
                (datetime.now(UTC).isoformat(), sub_id),
            )
            self._conn.commit()

    def _on_order_created(self, data: dict, meta: dict) -> None:
        attrs     = data.get("attributes", {})
        custom    = meta.get("custom_data") or {}
        tenant_id = custom.get("tenant_id", "")
        if not tenant_id:
            return
        # For orders (non-subscription), derive plan from first_order_item variant
        first_item  = (attrs.get("first_order_item") or {})
        variant_id  = str(first_item.get("variant_id", ""))
        plan        = _variant_to_plan(variant_id)
        customer_id = str(attrs.get("customer_id", ""))
        self._upsert(tenant_id, customer_id, "", plan, "active", None)

    def _set_status_by_sub(self, sub_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE subscriptions SET status=?, updated_at=?"
                " WHERE ls_sub_id=?",
                (status, datetime.now(UTC).isoformat(), sub_id),
            )
            self._conn.commit()

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _upsert(
        self,
        tenant_id:   str,
        customer_id: str,
        sub_id:      str,
        plan:        str,
        status:      str,
        renews_at:   str | None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO subscriptions
                    (tenant_id, ls_customer_id, ls_sub_id,
                     plan, status, renews_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    ls_customer_id = excluded.ls_customer_id,
                    ls_sub_id      = excluded.ls_sub_id,
                    plan           = excluded.plan,
                    status         = excluded.status,
                    renews_at      = excluded.renews_at,
                    updated_at     = excluded.updated_at
                """,
                (tenant_id, customer_id, sub_id, plan, status, renews_at, now),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# ── Module-level singleton ────────────────────────────────────────────────────

_instance:      LemonBilling | None = None
_instance_lock: threading.Lock      = threading.Lock()


def get_lemon_billing() -> LemonBilling:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = LemonBilling()
    return _instance


# ── Backwards-compatibility shim ─────────────────────────────────────────────
# Old code that imports get_paddle_billing() continues to work transparently.

def get_paddle_billing() -> LemonBilling:
    return get_lemon_billing()
