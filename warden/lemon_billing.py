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

from warden.config import settings
from warden.db.connect import open_persistent_db
from warden.db.ddl_registry import register

log = logging.getLogger("warden.lemon_billing")

_LS_API_KEY            = settings.lemonsqueezy_api_key
_LS_STORE_ID           = settings.lemonsqueezy_store_id
_LS_WEBHOOK_SECRET     = settings.lemonsqueezy_webhook_secret
_LS_VARIANT_TRIAL      = settings.lemonsqueezy_variant_trial
_LS_VARIANT_INDIVIDUAL = settings.lemonsqueezy_variant_individual
_LS_VARIANT_COMMUNITY  = settings.lemonsqueezy_variant_community
_LS_VARIANT_PRO        = settings.lemonsqueezy_variant_pro
_LS_VARIANT_ENTERPRISE = settings.lemonsqueezy_variant_enterprise

# Metered billing: flush x402 usage to LS after this many events or seconds
_METER_FLUSH_EVENTS = settings.ls_meter_flush_events
_METER_FLUSH_SECS   = settings.ls_meter_flush_secs

_LS_API_BASE = "https://api.lemonsqueezy.com/v1"


def _db_path() -> Path:
    """Resolved lazily so test env vars set after import are respected."""
    return Path(os.getenv("LEMONSQUEEZY_DB_PATH", "/warden/data/lemon.db"))


_LEMON_BILLING_DDL = """
    CREATE TABLE IF NOT EXISTS subscriptions (
        tenant_id         TEXT PRIMARY KEY,
        ls_customer_id    TEXT,
        ls_sub_id         TEXT,
        ls_sub_item_id    TEXT,
        plan              TEXT NOT NULL DEFAULT 'starter',
        status            TEXT NOT NULL DEFAULT 'active',
        renews_at         TEXT,
        updated_at        TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_subs_ls_sub
        ON subscriptions(ls_sub_id);
    CREATE TABLE IF NOT EXISTS webhook_events (
        event_id        TEXT PRIMARY KEY,
        event_name      TEXT NOT NULL,
        processed_at    TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tenant_feature_flags (
        tenant_id                TEXT PRIMARY KEY,
        post_quantum_cryptography INTEGER NOT NULL DEFAULT 0,
        sova_agent               INTEGER NOT NULL DEFAULT 0,
        marketplace_node         INTEGER NOT NULL DEFAULT 0,
        updated_at               TEXT NOT NULL
    );
"""
register("lemon_billing", "warden.lemon_billing", _LEMON_BILLING_DDL)


# ── Plan definitions ──────────────────────────────────────────────────────────

PLAN_QUOTAS: dict[str, int | None] = {
    "trial":            1_000,   # 14-day trial — same quota as starter
    "starter":          1_000,
    "individual":       5_000,   # usage-based metered billing via x402
    "community_business": 10_000,
    "pro":              50_000,
    "enterprise":       None,    # unlimited
}

# Tier prices (USD/month) — MoR: Lemon Squeezy
PLAN_PRICES: dict[str, float] = {
    "trial":              0.00,   # $0 for 14 days
    "starter":            0.00,
    "individual":         5.00,   # + $0.000001/search via x402 metered billing
    "community_business": 39.99,  # + 1.5% take rate on cleared M2M transactions
    "pro":                99.99,  # + sponsored listings boost included
    "enterprise":        249.00,  # + PQC + Sovereign + dedicated Opus routing
}

# Backwards-compat aliases used by existing quota checks
PLAN_QUOTAS["free"] = PLAN_QUOTAS["starter"]
PLAN_QUOTAS["msp"]  = PLAN_QUOTAS["enterprise"]


def _variant_to_plan(variant_id: str) -> str:
    # Build mapping only for configured (non-empty) variant IDs to avoid
    # duplicate "" keys when env vars are unset (last key wins → wrong plan).
    # _LS_VARIANT_TRIAL maps to "trial" — LS Trials feature handles the 14-day gate.
    mapping: dict[str, str] = {}
    if _LS_VARIANT_TRIAL:
        mapping[_LS_VARIANT_TRIAL]      = "trial"
    if _LS_VARIANT_INDIVIDUAL:
        mapping[_LS_VARIANT_INDIVIDUAL] = "individual"
    if _LS_VARIANT_COMMUNITY:
        mapping[_LS_VARIANT_COMMUNITY]  = "community_business"
    if _LS_VARIANT_PRO:
        mapping[_LS_VARIANT_PRO]        = "pro"
    if _LS_VARIANT_ENTERPRISE:
        mapping[_LS_VARIANT_ENTERPRISE] = "enterprise"
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

    # ── Internal ──────────────────────────────────────────────────────────────

    def _open(self) -> sqlite3.Connection:
        return open_persistent_db("lemon_billing", str(self._path))

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
        cancel_url:     str,       # accepted for API compat; LS manages its own cancel flow
        customer_email: str | None = None,
        agent_id:       str | None = None,   # marketplace DID — stored in custom_data for webhook binding
    ) -> str:
        """
        Create a Lemon Squeezy checkout and return the hosted URL.

        Note: ``cancel_url`` is accepted for API compatibility with Stripe-style callers
        but is not forwarded to LS — Lemon Squeezy handles checkout abandonment
        internally and does not expose a cancel redirect URL in its Checkouts API.
        Only ``success_url`` (mapped to ``redirect_url``) is sent.
        """
        if not self._enabled:
            raise RuntimeError("Lemon Squeezy not configured (LEMONSQUEEZY_API_KEY missing).")

        variant_map = {
            "trial":              _LS_VARIANT_TRIAL,
            "individual":         _LS_VARIANT_INDIVIDUAL,
            "community_business": _LS_VARIANT_COMMUNITY,
            "smb":                _LS_VARIANT_COMMUNITY,   # alias
            "pro":                _LS_VARIANT_PRO,
            "enterprise":         _LS_VARIANT_ENTERPRISE,
            "msp":                _LS_VARIANT_ENTERPRISE,  # alias
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
                        "custom": {
                            "tenant_id": tenant_id,
                            **({"agent_id": agent_id} if agent_id else {}),
                        },
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

        When the tenant has an active LS subscription, returns the customer-scoped
        billing portal URL (pre-filtered to their orders).  Falls back to the
        generic orders page for tenants without a subscription record.
        """
        row = self._conn.execute(
            "SELECT ls_customer_id FROM subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()

        if row and row["ls_customer_id"]:
            # Deep-link to this customer's order history in the LS portal.
            # The customer_id is the numeric LS customer ID stored at webhook time.
            cid = row["ls_customer_id"]
            return f"https://app.lemonsqueezy.com/my-orders?customer_id={cid}"

        return "https://app.lemonsqueezy.com/my-orders"

    # ── Webhook handler ───────────────────────────────────────────────────────

    def handle_webhook(self, payload: bytes, signature_header: str) -> str:
        """
        Validate and process a Lemon Squeezy webhook event.

        X-Signature header: HMAC-SHA256 hex digest of the raw payload.
        Returns the event_name string.
        Raises ValueError on invalid signature.
        """
        if _LS_WEBHOOK_SECRET:
            # Fail-closed: if webhook secret is configured, a missing or invalid
            # X-Signature header is always rejected — prevents privilege-escalation
            # via forged webhooks even if the attacker omits the header entirely.
            if not signature_header:
                raise ValueError("Missing X-Signature on Lemon Squeezy webhook.")
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
        event_id   = str(meta.get("event_id") or meta.get("uuid") or "")
        data       = event.get("data", {})

        # Idempotency: skip events already processed (Lemon Squeezy retries on timeout)
        if event_id:
            with self._lock:
                row = self._conn.execute(
                    "SELECT event_id FROM webhook_events WHERE event_id=?", (event_id,)
                ).fetchone()
                if row:
                    log.info("LemonSqueezy: duplicate event_id=%s (%s) — skipped.", event_id, event_name)
                    return event_name
                self._conn.execute(
                    "INSERT INTO webhook_events(event_id, event_name, processed_at) VALUES(?,?,?)",
                    (event_id, event_name, datetime.now(UTC).isoformat()),
                )
                self._conn.commit()

        if event_name in ("subscription_created", "subscription_updated", "subscription_resumed"):
            self._on_subscription_active(data, meta)
        elif event_name == "subscription_trial_started":
            self._on_trial_started(data, meta)
        elif event_name == "subscription_trial_ended":
            # Trial expired without conversion → downgrade to starter
            self._on_trial_ended(data)
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

        # Extract subscription_item_id for metered billing
        # LS embeds first_subscription_item in the subscription attributes
        first_item  = attrs.get("first_subscription_item") or {}
        sub_item_id = str(first_item.get("id", ""))

        self._upsert(tenant_id, customer_id, sub_id, plan, status, renews_at, sub_item_id)
        self._enforce_feature_flags(tenant_id, plan)
        log.info("LemonSqueezy: tenant %s activated plan=%s item=%s.", tenant_id, plan, sub_item_id[:16] if sub_item_id else "—")

    def _enforce_feature_flags(self, tenant_id: str, plan: str) -> None:
        """
        Gate PQC and SOVA access to their minimum plan tier.
        Called on every subscription change so downgrades are enforced immediately.

        PQC (post_quantum_cryptography) → Enterprise only
        SOVA agent                       → Pro and above
        Marketplace node                 → Community Business and above
        """
        metered_tiers = ("individual", "community_business", "pro", "enterprise")
        pro_tiers     = ("pro", "enterprise")
        ent_tiers     = ("enterprise",)

        self.set_feature_flags(
            tenant_id,
            post_quantum_cryptography = plan in ent_tiers,
            sova_agent                = plan in pro_tiers,
            marketplace_node          = plan in metered_tiers,
        )

    def _on_subscription_cancelled(self, data: dict) -> None:
        sub_id = str(data.get("id", ""))
        with self._lock:
            self._conn.execute(
                "UPDATE subscriptions SET plan='starter', status='cancelled', updated_at=?"
                " WHERE ls_sub_id=?",
                (datetime.now(UTC).isoformat(), sub_id),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT tenant_id FROM subscriptions WHERE ls_sub_id=?", (sub_id,)
            ).fetchone()
        if row:
            self._enforce_feature_flags(row["tenant_id"], "starter")

    def _on_trial_started(self, data: dict, meta: dict) -> None:
        """LS fires subscription_trial_started — grant trial access immediately."""
        attrs       = data.get("attributes", {})
        custom      = meta.get("custom_data") or {}
        tenant_id   = custom.get("tenant_id", "")
        if not tenant_id:
            log.warning("LemonSqueezy: trial_started missing tenant_id.")
            return
        sub_id      = str(data.get("id", ""))
        customer_id = str(attrs.get("customer_id", ""))
        trial_ends  = attrs.get("trial_ends_at") or attrs.get("renews_at")
        self._upsert(tenant_id, customer_id, sub_id, "trial", "on_trial", trial_ends)
        log.info("LemonSqueezy: tenant %s trial started, ends %s.", tenant_id, trial_ends)

    def _on_trial_ended(self, data: dict) -> None:
        """LS fires subscription_trial_ended without conversion → downgrade to starter."""
        sub_id = str(data.get("id", ""))
        with self._lock:
            self._conn.execute(
                "UPDATE subscriptions SET plan='starter', status='active', updated_at=?"
                " WHERE ls_sub_id=?",
                (datetime.now(UTC).isoformat(), sub_id),
            )
            self._conn.commit()
            row = self._conn.execute(
                "SELECT tenant_id FROM subscriptions WHERE ls_sub_id=?", (sub_id,)
            ).fetchone()
        if row:
            self._enforce_feature_flags(row["tenant_id"], "starter")
        log.info("LemonSqueezy: trial ended sub=%s → downgraded to starter.", sub_id)

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
        tenant_id:    str,
        customer_id:  str,
        sub_id:       str,
        plan:         str,
        status:       str,
        renews_at:    str | None,
        sub_item_id:  str = "",
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO subscriptions
                    (tenant_id, ls_customer_id, ls_sub_id, ls_sub_item_id,
                     plan, status, renews_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    ls_customer_id  = excluded.ls_customer_id,
                    ls_sub_id       = excluded.ls_sub_id,
                    ls_sub_item_id  = CASE
                        WHEN excluded.ls_sub_item_id != '' THEN excluded.ls_sub_item_id
                        ELSE ls_sub_item_id
                    END,
                    plan       = excluded.plan,
                    status     = excluded.status,
                    renews_at  = excluded.renews_at,
                    updated_at = excluded.updated_at
                """,
                (tenant_id, customer_id, sub_id, sub_item_id, plan, status, renews_at, now),
            )
            self._conn.commit()

    # ── Usage-Based Billing (Metered API) ────────────────────────────────────

    async def report_usage(
        self,
        subscription_item_id: str,
        quantity: int,
        action: str = "increment",
    ) -> dict:
        """
        POST a single usage record to Lemon Squeezy Metered Billing API.

        Sends the JSON:API payload required by LS /v1/usage-records.
        Fail-open: network/API errors are logged and an error dict is returned
        (never raised) so callers can fire-and-forget via BackgroundTasks.

        Args:
            subscription_item_id: LS subscription item ID (ls_sub_item_id column)
            quantity:             Number of units consumed (integer)
            action:               "increment" (default) or "set"
        """
        if not _LS_API_KEY:
            return {"status": "skipped", "reason": "LEMONSQUEEZY_API_KEY not configured"}

        payload = {
            "data": {
                "type": "usage-records",
                "attributes": {
                    "quantity": quantity,
                    "action":   action,
                },
                "relationships": {
                    "subscription-item": {
                        "data": {"type": "subscription-items", "id": subscription_item_id}
                    }
                },
            }
        }
        try:
            import asyncio  # noqa: PLC0415
            loop = asyncio.get_running_loop()
            resp = await loop.run_in_executor(
                None,
                lambda: _ls_request("POST", "/usage-records", payload),
            )
            log.debug(
                "report_usage: item=%s qty=%d action=%s → 200",
                subscription_item_id[:16], quantity, action,
            )
            return {"status": "ok", "quantity": quantity, "response": resp}
        except Exception as exc:
            log.warning("report_usage fail-open: item=%s error=%s", subscription_item_id[:16], exc)
            return {"status": "error", "error": str(exc)}

    # ── Feature flags ─────────────────────────────────────────────────────────

    def set_feature_flags(self, tenant_id: str, **flags: bool) -> None:
        """Upsert boolean feature flags for a tenant (PQC, SOVA, etc.)."""
        allowed = {"post_quantum_cryptography", "sova_agent", "marketplace_node"}
        cols = {k: v for k, v in flags.items() if k in allowed}
        if not cols:
            return
        now = datetime.now(UTC).isoformat()
        set_clause = ", ".join(f"{k}=?" for k in cols)
        vals = [int(v) for v in cols.values()] + [now, tenant_id]
        with self._lock:
            # Ensure row exists
            self._conn.execute(
                "INSERT OR IGNORE INTO tenant_feature_flags"
                " (tenant_id, post_quantum_cryptography, sova_agent, marketplace_node, updated_at)"
                " VALUES (?, 0, 0, 0, ?)",
                (tenant_id, now),
            )
            self._conn.execute(
                f"UPDATE tenant_feature_flags SET {set_clause}, updated_at=?"  # noqa: S608
                " WHERE tenant_id=?",
                vals,
            )
            self._conn.commit()
        log.info("feature_flags: tenant=%s flags=%s", tenant_id[:16], cols)

    def get_feature_flags(self, tenant_id: str) -> dict[str, bool]:
        """Return feature flags for a tenant; defaults False when no row exists."""
        row = self._conn.execute(
            "SELECT post_quantum_cryptography, sova_agent, marketplace_node"
            " FROM tenant_feature_flags WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            return {"post_quantum_cryptography": False, "sova_agent": False, "marketplace_node": False}
        return {
            "post_quantum_cryptography": bool(row["post_quantum_cryptography"]),
            "sova_agent":               bool(row["sova_agent"]),
            "marketplace_node":         bool(row["marketplace_node"]),
        }

    # ── Dunning ───────────────────────────────────────────────────────────────

    def expire_past_due(self, cutoff_iso: str) -> list[dict]:
        """
        Downgrade subscriptions in 'past_due' whose updated_at < cutoff_iso.

        Called by the dunning worker after the grace period expires.
        Returns a list of {tenant_id, plan} for each downgraded row.
        """
        now = datetime.now(UTC).isoformat()
        with self._lock:
            rows = self._conn.execute(
                "SELECT tenant_id, plan FROM subscriptions "
                "WHERE status='past_due' AND updated_at < ?",
                (cutoff_iso,),
            ).fetchall()
            if not rows:
                return []
            ids = [r["tenant_id"] for r in rows]
            placeholders = ",".join("?" * len(ids))
            self._conn.execute(
                f"UPDATE subscriptions SET plan='starter', status='expired', updated_at=?"
                f" WHERE tenant_id IN ({placeholders})",
                [now, *ids],
            )
            self._conn.commit()
        log.info("dunning: expired %d past_due subscriptions.", len(rows))
        return [{"tenant_id": r["tenant_id"], "plan": r["plan"]} for r in rows]

    def close(self) -> None:
        self._conn.close()


# ── Metered usage aggregator (x402 nanopayments → LS usage billing) ──────────

class MeterUsageAggregator:
    """Aggregates x402 search-call micro-events and batch-reports them to
    Lemon Squeezy's usage-based billing API (POST /v1/usage-records).

    Usage model for Individual tier:
      - Per-call fee: $0.000001 (MARKETPLACE_SEARCH_FEE_USD)
      - Flush to LS after _METER_FLUSH_EVENTS events OR _METER_FLUSH_SECS seconds
      - Fail-open: flush errors are logged, not raised

    Rule #14: deductions are batched, never per-call on-chain.
    """

    def __init__(self) -> None:
        self._lock:        threading.Lock          = threading.Lock()
        self._pending:     dict[str, list[float]]  = {}  # tenant_id → [amount_usd, ...]
        self._last_flush:  float                   = 0.0

    def record(self, tenant_id: str, amount_usd: float) -> None:
        """Record one usage event. Thread-safe."""
        with self._lock:
            self._pending.setdefault(tenant_id, []).append(amount_usd)
            total_events = sum(len(v) for v in self._pending.values())

        import time
        age = time.time() - self._last_flush
        if total_events >= _METER_FLUSH_EVENTS or age >= _METER_FLUSH_SECS:
            self.flush()

    def flush(self) -> None:
        """Send all pending usage records to LS. Fail-open."""
        import time
        with self._lock:
            snapshot   = dict(self._pending)
            self._pending.clear()
            self._last_flush = time.time()

        if not snapshot or not _LS_API_KEY:
            return

        billing = get_lemon_billing()
        for tenant_id, amounts in snapshot.items():
            try:
                row = billing._conn.execute(
                    "SELECT ls_sub_item_id FROM subscriptions"
                    " WHERE tenant_id=? AND plan IN ('individual','community_business')"
                    " AND status IN ('active','on_trial')",
                    (tenant_id,),
                ).fetchone()
                if not row or not row["ls_sub_item_id"]:
                    continue
                quantity = len(amounts)
                _ls_request("POST", "/usage-records", {
                    "data": {
                        "type": "usage-records",
                        "attributes": {
                            "quantity": quantity,
                            "action":   "increment",
                        },
                        "relationships": {
                            "subscription-item": {
                                "data": {
                                    "type": "subscription-items",
                                    "id":   row["ls_sub_item_id"],
                                }
                            }
                        },
                    }
                })
                log.info("MeterUsage: flushed %d events for tenant %s.", quantity, tenant_id[:8])
            except Exception as exc:
                log.warning("MeterUsage: flush error tenant=%s: %s", tenant_id[:8], exc)


_meter_aggregator: MeterUsageAggregator | None = None
_meter_lock: threading.Lock = threading.Lock()


def get_meter_aggregator() -> MeterUsageAggregator:
    global _meter_aggregator
    if _meter_aggregator is None:
        with _meter_lock:
            if _meter_aggregator is None:
                _meter_aggregator = MeterUsageAggregator()
    return _meter_aggregator


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
