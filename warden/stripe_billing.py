"""
warden/stripe_billing.py — REMOVED
────────────────────────────────────
Stripe has been replaced by Lemon Squeezy.
All billing is now handled by warden/lemon_billing.py.
THIS FILE IS DEPRECATED — do not import it directly.


Plan tiers (Warden Identity domain-based billing)
──────────────────────────────────────────────────
  free    —    1 000 req/month / domain,   $0/month  (default, trial)
  startup —   50 000 req/month / domain,  $99/month  (≤ 50 employees)
  growth  —  250 000 req/month / domain, $299/month  (≤ 250 employees)
  msp     — Unlimited req/month / domain,  custom    (MSP / reseller)

Per-minute burst caps (enforced by plan-aware rate limiter at the gateway)
─────────────────────────────────────────────────────────────────────────
  free    —  10 req/min per tenant (prevents abuse of the trial tier)
  startup —  60 req/min per tenant
  growth  — 200 req/min per tenant
  msp     — 500 req/min per tenant (configurable via PLAN_RATE_LIMITS)

Webhook idempotency
───────────────────
  Stripe re-delivers events on network errors or timeout (up to 3 days,
  exponential backoff).  Every event is stored in ``webhook_events`` with
  its Stripe event_id as PRIMARY KEY.  A second delivery of the same
  event_id is a no-op — the subscriber state never mutates twice.

Lifecycle
─────────
  1. Stripe Checkout → POST /subscription/checkout → returns hosted URL
  2. stripe.checkout.session.completed webhook → activates domain in:
       a. SQLite subscriptions table (source of truth)
       b. Redis HSET warden:oidc:domains <domain> <tenant_id>
          (O(1) enforcement at OIDC auth time, < 0.5 ms)
  3. customer.subscription.deleted / invoice.payment_failed webhook →
       removes domain from Redis → next OIDC auth returns HTTP 402
  4. Extension shows graceful 402 UI ("Contact your IT admin").

Environment variables
─────────────────────
  STRIPE_SECRET_KEY        — sk_live_… or sk_test_…
  STRIPE_WEBHOOK_SECRET    — whsec_… (Stripe Dashboard → Webhooks)
  STRIPE_PRICE_STARTUP     — price_… for the Startup plan ($99/mo)
  STRIPE_PRICE_GROWTH      — price_… for the Growth plan  ($299/mo)
  STRIPE_PRICE_MSP         — price_… for the MSP plan     (custom)
  STRIPE_DB_PATH           — SQLite path (default /warden/data/stripe.db)

Thread-safe: all writes protected by threading.Lock + WAL journal mode.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger("warden.stripe_billing")

_STRIPE_SECRET_KEY      = os.getenv("STRIPE_SECRET_KEY", "")
_STRIPE_WEBHOOK_SECRET  = os.getenv("STRIPE_WEBHOOK_SECRET", "")
_STRIPE_PRICE_STARTUP   = os.getenv("STRIPE_PRICE_STARTUP", "")
_STRIPE_PRICE_GROWTH    = os.getenv("STRIPE_PRICE_GROWTH", "")
_STRIPE_PRICE_MSP       = os.getenv("STRIPE_PRICE_MSP", "")
_DB_PATH                = Path(os.getenv("STRIPE_DB_PATH", "/warden/data/stripe.db"))

# ── Plan definitions ──────────────────────────────────────────────────────────

#: Monthly request quota per plan (None = unlimited)
PLAN_QUOTAS: dict[str, int | None] = {
    "free":    1_000,
    "startup": 50_000,
    "growth":  250_000,
    "msp":     None,
}

#: Per-minute burst cap per plan (enforced by the gateway rate limiter)
PLAN_RATE_LIMITS: dict[str, int] = {
    "free":    10,
    "startup": 60,
    "growth":  200,
    "msp":     500,
}

#: Stripe price ID → plan name (built at import time from env vars)
_PRICE_TO_PLAN: dict[str, str] = {}


def _build_price_map() -> None:
    if _STRIPE_PRICE_STARTUP:
        _PRICE_TO_PLAN[_STRIPE_PRICE_STARTUP] = "startup"
    if _STRIPE_PRICE_GROWTH:
        _PRICE_TO_PLAN[_STRIPE_PRICE_GROWTH] = "growth"
    if _STRIPE_PRICE_MSP:
        _PRICE_TO_PLAN[_STRIPE_PRICE_MSP] = "msp"


_build_price_map()


# ── StripeBilling ─────────────────────────────────────────────────────────────

class StripeBilling:
    """Manages Stripe subscriptions and plan state per tenant."""

    def __init__(self, db_path: Path = _DB_PATH) -> None:
        self._enabled = bool(_STRIPE_SECRET_KEY)
        self._path    = db_path
        self._lock    = threading.Lock()

        if self._enabled:
            import stripe as _stripe  # noqa: PLC0415
            _stripe.api_key = _STRIPE_SECRET_KEY

        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = self._open()
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
                    tenant_id              TEXT PRIMARY KEY,
                    stripe_customer_id     TEXT,
                    stripe_subscription_id TEXT,
                    plan                   TEXT NOT NULL DEFAULT 'free',
                    status                 TEXT NOT NULL DEFAULT 'active',
                    current_period_end     TEXT,
                    admin_email            TEXT,
                    updated_at             TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_subs_customer
                    ON subscriptions(stripe_customer_id);

                CREATE TABLE IF NOT EXISTS webhook_events (
                    event_id    TEXT PRIMARY KEY,
                    event_type  TEXT NOT NULL,
                    processed_at TEXT NOT NULL
                );
            """)
            self._conn.commit()

        # Migrate existing DBs: add admin_email column if missing (SQLite
        # doesn't support IF NOT EXISTS on ALTER TABLE)
        try:
            self._conn.execute("ALTER TABLE subscriptions ADD COLUMN admin_email TEXT")
            self._conn.commit()
        except Exception:
            pass  # column already exists — ignore

    # ── Plan / quota queries ──────────────────────────────────────────────────

    def get_plan(self, tenant_id: str) -> str:
        """Return current plan name for tenant_id (defaults to 'free')."""
        row = self._conn.execute(
            "SELECT plan, status FROM subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            return "free"
        # Treat non-active statuses as free
        if row["status"] not in ("active", "trialing"):
            return "free"
        return row["plan"]

    def get_quota(self, tenant_id: str) -> int | None:
        """Return monthly request quota for tenant (None = unlimited)."""
        return PLAN_QUOTAS.get(self.get_plan(tenant_id), PLAN_QUOTAS["free"])

    def get_rate_limit_per_minute(self, tenant_id: str) -> int:
        """Return per-minute burst cap for tenant based on current plan."""
        return PLAN_RATE_LIMITS.get(self.get_plan(tenant_id), PLAN_RATE_LIMITS["free"])

    def get_status(self, tenant_id: str) -> dict:
        """Return full subscription status dict for a tenant."""
        row = self._conn.execute(
            "SELECT * FROM subscriptions WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        plan = self.get_plan(tenant_id)
        return {
            "tenant_id":        tenant_id,
            "plan":             plan,
            "quota":            PLAN_QUOTAS.get(plan),
            "rate_limit_per_min": PLAN_RATE_LIMITS.get(plan, PLAN_RATE_LIMITS["free"]),
            "status":           row["status"] if row else "free",
            "period_end":       row["current_period_end"] if row else None,
            "customer_id":      row["stripe_customer_id"] if row else None,
        }

    # ── Stripe Checkout ───────────────────────────────────────────────────────

    def create_checkout_session(
        self,
        tenant_id:      str,
        plan:           str,
        success_url:    str,
        cancel_url:     str,
        customer_email: str | None = None,
    ) -> str:
        """
        Create a Stripe Checkout session and return the hosted payment URL.

        Raises RuntimeError if Stripe is not configured.
        Raises ValueError on invalid plan.
        """
        if not self._enabled:
            raise RuntimeError("Stripe not configured (STRIPE_SECRET_KEY missing).")
        if plan not in ("startup", "growth", "msp"):
            raise ValueError(f"Invalid plan {plan!r}. Choose 'startup', 'growth', or 'msp'.")

        price_map = {
            "startup": _STRIPE_PRICE_STARTUP,
            "growth":  _STRIPE_PRICE_GROWTH,
            "msp":     _STRIPE_PRICE_MSP,
        }
        price_id = price_map[plan]
        if not price_id:
            raise RuntimeError(
                f"STRIPE_PRICE_{plan.upper()} env var not set. "
                "Create a recurring price in the Stripe Dashboard and set it here."
            )

        import stripe as _stripe  # noqa: PLC0415

        # Re-use an existing Stripe customer if available
        row = self._conn.execute(
            "SELECT stripe_customer_id FROM subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        customer_id = row["stripe_customer_id"] if row else None

        params: dict = {
            "mode":       "subscription",
            "line_items": [{"price": price_id, "quantity": 1}],
            "success_url": success_url,
            "cancel_url":  cancel_url,
            "metadata":    {"tenant_id": tenant_id},
            "subscription_data": {"metadata": {"tenant_id": tenant_id}},
        }
        if customer_id:
            params["customer"] = customer_id
        elif customer_email:
            params["customer_email"] = customer_email

        session = _stripe.checkout.Session.create(**params)
        log.info(
            "Stripe: checkout session %s created (tenant=%s plan=%s).",
            session.id, tenant_id, plan,
        )
        return session.url  # type: ignore[return-value]

    # ── Billing Portal ────────────────────────────────────────────────────────

    def create_portal_session(self, tenant_id: str, return_url: str) -> str:
        """
        Return a Stripe Billing Portal URL for self-serve plan management.

        Raises RuntimeError if Stripe is not configured.
        Raises ValueError if no Stripe customer exists for this tenant.
        """
        if not self._enabled:
            raise RuntimeError("Stripe not configured (STRIPE_SECRET_KEY missing).")

        row = self._conn.execute(
            "SELECT stripe_customer_id FROM subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if not row or not row["stripe_customer_id"]:
            raise ValueError(
                f"No Stripe customer found for tenant {tenant_id!r}. "
                "The tenant must complete a checkout session first."
            )

        import stripe as _stripe  # noqa: PLC0415

        session = _stripe.billing_portal.Session.create(
            customer=row["stripe_customer_id"],
            return_url=return_url,
        )
        return session.url  # type: ignore[return-value]

    # ── Webhook handler ───────────────────────────────────────────────────────

    def handle_webhook(self, payload: bytes, sig_header: str) -> str:
        """
        Validate and process a Stripe webhook event.

        Returns the event type string.
        Raises ValueError on invalid signature.
        Raises RuntimeError if Stripe is not configured.

        Idempotent: duplicate deliveries of the same event_id are no-ops.
        """
        if not self._enabled:
            raise RuntimeError("Stripe not configured (STRIPE_SECRET_KEY missing).")

        import stripe as _stripe  # noqa: PLC0415

        try:
            event = _stripe.Webhook.construct_event(
                payload, sig_header, _STRIPE_WEBHOOK_SECRET
            )
        except _stripe.error.SignatureVerificationError as exc:
            raise ValueError("Invalid Stripe webhook signature.") from exc

        event_id = event["id"]
        etype    = event["type"]

        # ── Idempotency check ─────────────────────────────────────────────────
        with self._lock:
            existing = self._conn.execute(
                "SELECT event_id FROM webhook_events WHERE event_id=?", (event_id,)
            ).fetchone()
            if existing:
                log.info("Stripe webhook: %s (%s) already processed — skipping.", etype, event_id)
                return etype
            self._conn.execute(
                "INSERT INTO webhook_events (event_id, event_type, processed_at) VALUES (?, ?, ?)",
                (event_id, etype, datetime.now(UTC).isoformat()),
            )
            self._conn.commit()

        # ── Event dispatch ────────────────────────────────────────────────────
        data = event["data"]["object"]

        if etype == "checkout.session.completed":
            self._on_checkout_completed(data)
        elif etype in ("customer.subscription.created", "customer.subscription.updated"):
            self._on_subscription_updated(data)
        elif etype == "customer.subscription.deleted":
            self._on_subscription_deleted(data)
        elif etype == "invoice.paid":
            sub_id = data.get("subscription")
            if sub_id:
                self._refresh_subscription(sub_id)
        elif etype == "invoice.payment_failed":
            sub_id = data.get("subscription")
            if sub_id:
                self._set_status_by_sub(sub_id, "past_due")
                self._redis_remove_by_sub(sub_id)

        log.info("Stripe webhook: %s (%s) processed.", etype, event_id)
        return etype

    # ── Webhook sub-handlers ──────────────────────────────────────────────────

    def _on_checkout_completed(self, session: dict) -> None:
        tenant_id   = (session.get("metadata") or {}).get("tenant_id", "")
        customer_id = session.get("customer", "")
        sub_id      = session.get("subscription", "")
        if not tenant_id:
            log.warning("Stripe: checkout.session.completed missing tenant_id in metadata.")
            return

        # Capture billing admin email from checkout session
        admin_email: str | None = (
            session.get("customer_email")
            or (session.get("customer_details") or {}).get("email")
        ) or None

        import stripe as _stripe  # noqa: PLC0415

        sub = _stripe.Subscription.retrieve(sub_id) if sub_id else None
        plan, period_end, status = self._extract_sub_fields(sub)
        self._upsert(tenant_id, customer_id, sub_id, plan, status, period_end, admin_email)
        log.info("Stripe: tenant %s activated plan=%s email=%s.", tenant_id, plan, admin_email)

    def _on_subscription_updated(self, sub: dict) -> None:
        tenant_id = (sub.get("metadata") or {}).get("tenant_id", "")
        if not tenant_id:
            # Fall back to lookup by Stripe customer ID
            cid = sub.get("customer", "")
            row = self._conn.execute(
                "SELECT tenant_id FROM subscriptions WHERE stripe_customer_id=?", (cid,)
            ).fetchone()
            tenant_id = row["tenant_id"] if row else ""
        if not tenant_id:
            return

        plan, period_end, status = self._extract_sub_fields(sub)
        self._upsert(
            tenant_id, sub.get("customer", ""), sub.get("id", ""),
            plan, status, period_end,
        )

    def _on_subscription_deleted(self, sub: dict) -> None:
        sub_id = sub.get("id", "")
        with self._lock:
            self._conn.execute(
                "UPDATE subscriptions SET plan='free', status='cancelled', updated_at=?"
                " WHERE stripe_subscription_id=?",
                (datetime.now(UTC).isoformat(), sub_id),
            )
            self._conn.commit()
        self._redis_remove_by_sub(sub_id)

    def _refresh_subscription(self, sub_id: str) -> None:
        import stripe as _stripe  # noqa: PLC0415
        sub = _stripe.Subscription.retrieve(sub_id)
        self._on_subscription_updated(sub)

    def _set_status_by_sub(self, sub_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE subscriptions SET status=?, updated_at=?"
                " WHERE stripe_subscription_id=?",
                (status, datetime.now(UTC).isoformat(), sub_id),
            )
            self._conn.commit()

    # ── Redis enforcement ─────────────────────────────────────────────────────

    def _redis_activate(self, tenant_id: str) -> None:
        """
        Write warden:oidc:billing:<tenant_id> = '1' so oidc_guard grants access.
        No-op when Redis is unavailable (fail-open for billing enforcement).
        """
        try:
            from warden.cache import _get_client as get_redis  # noqa: PLC0415
            r = get_redis()
            r.set(f"warden:oidc:billing:{tenant_id}", "1")
            log.debug("Redis: activated billing key for tenant %s.", tenant_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("Redis billing activate failed (tenant=%s): %s", tenant_id, exc)

    def _redis_deactivate(self, tenant_id: str) -> None:
        """
        Delete warden:oidc:billing:<tenant_id> so next OIDC auth returns HTTP 402.
        No-op when Redis is unavailable.
        """
        try:
            from warden.cache import _get_client as get_redis  # noqa: PLC0415
            r = get_redis()
            r.delete(f"warden:oidc:billing:{tenant_id}")
            log.debug("Redis: deactivated billing key for tenant %s.", tenant_id)
        except Exception as exc:  # noqa: BLE001
            log.warning("Redis billing deactivate failed (tenant=%s): %s", tenant_id, exc)

    def _redis_remove_by_sub(self, sub_id: str) -> None:
        """Look up tenant_id from sub_id and deactivate in Redis."""
        row = self._conn.execute(
            "SELECT tenant_id FROM subscriptions WHERE stripe_subscription_id=?", (sub_id,)
        ).fetchone()
        if row:
            self._redis_deactivate(row["tenant_id"])

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_sub_fields(
        sub: object | None,
    ) -> tuple[str, str | None, str]:
        """Return (plan, period_end_iso, status) from a Stripe Subscription."""
        if sub is None:
            return "free", None, "active"

        items    = (sub.get("items") or {}).get("data", []) if hasattr(sub, "get") else []  # type: ignore[union-attr]
        price_id = items[0]["price"]["id"] if items else ""
        plan     = _PRICE_TO_PLAN.get(price_id, "startup")
        status   = sub.get("status", "active") if hasattr(sub, "get") else "active"  # type: ignore[union-attr]

        period_end_ts = sub.get("current_period_end") if hasattr(sub, "get") else None  # type: ignore[union-attr]
        period_end: str | None = None
        if period_end_ts:
            period_end = datetime.fromtimestamp(
                int(period_end_ts), tz=UTC
            ).isoformat()

        return plan, period_end, str(status)

    def _upsert(
        self,
        tenant_id:   str,
        customer_id: str,
        sub_id:      str,
        plan:        str,
        status:      str,
        period_end:  str | None,
        admin_email: str | None = None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO subscriptions
                    (tenant_id, stripe_customer_id, stripe_subscription_id,
                     plan, status, current_period_end, admin_email, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    stripe_customer_id     = excluded.stripe_customer_id,
                    stripe_subscription_id = excluded.stripe_subscription_id,
                    plan                   = excluded.plan,
                    status                 = excluded.status,
                    current_period_end     = excluded.current_period_end,
                    admin_email            = COALESCE(excluded.admin_email, subscriptions.admin_email),
                    updated_at             = excluded.updated_at
                """,
                (tenant_id, customer_id, sub_id, plan, status, period_end, admin_email, now),
            )
            self._conn.commit()

        # Push to Redis after successful DB write
        if status in ("active", "trialing"):
            self._redis_activate(tenant_id)
        else:
            self._redis_deactivate(tenant_id)

    def close(self) -> None:
        self._conn.close()


# ── Module-level singleton ────────────────────────────────────────────────────

_instance:      StripeBilling | None = None
_instance_lock: threading.Lock       = threading.Lock()


def get_stripe_billing() -> StripeBilling:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = StripeBilling()
    return _instance
