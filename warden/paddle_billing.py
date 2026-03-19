"""
warden/paddle_billing.py
────────────────────────
Paddle Billing subscription management for Shadow Warden AI.

Plans
─────
  free  — 1 000 req/month,  $0/month  (default, no Paddle required)
  pro   — 50 000 req/month, $49/month
  msp   — Unlimited,        $199/month

Lifecycle
─────────
  1. Client calls POST /billing/checkout → gets a Paddle hosted checkout URL
  2. After payment, Paddle fires transaction.completed webhook
  3. Webhook handler upserts the subscription row for that tenant
  4. Every /filter call reads get_quota(tenant_id) from this store

Environment variables
─────────────────────
  PADDLE_API_KEY         — API key from Paddle Dashboard (Developers → API keys)
  PADDLE_WEBHOOK_SECRET  — webhook secret (Paddle Dashboard → Notifications)
  PADDLE_PRICE_PRO       — price ID (pri_...) for the Pro plan
  PADDLE_PRICE_MSP       — price ID (pri_...) for the MSP plan
  PADDLE_SANDBOX         — "true" to use sandbox environment (default: false)
  PADDLE_DB_PATH         — SQLite path (default /warden/data/paddle.db)

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

log = logging.getLogger("warden.paddle_billing")

_PADDLE_API_KEY        = os.getenv("PADDLE_API_KEY", "")
_PADDLE_WEBHOOK_SECRET = os.getenv("PADDLE_WEBHOOK_SECRET", "")
_PADDLE_PRICE_PRO      = os.getenv("PADDLE_PRICE_PRO", "")
_PADDLE_PRICE_MSP      = os.getenv("PADDLE_PRICE_MSP", "")
_PADDLE_SANDBOX        = os.getenv("PADDLE_SANDBOX", "false").lower() == "true"
_DB_PATH               = Path(os.getenv("PADDLE_DB_PATH", "/warden/data/paddle.db"))

_API_BASE = (
    "https://sandbox-api.paddle.com" if _PADDLE_SANDBOX
    else "https://api.paddle.com"
)

# ── Plan definitions ──────────────────────────────────────────────────────────

PLAN_QUOTAS: dict[str, int | None] = {
    "free": 1_000,
    "pro":  50_000,
    "msp":  None,
}

_PRICE_TO_PLAN: dict[str, str] = {}


def _build_price_map() -> None:
    if _PADDLE_PRICE_PRO:
        _PRICE_TO_PLAN[_PADDLE_PRICE_PRO] = "pro"
    if _PADDLE_PRICE_MSP:
        _PRICE_TO_PLAN[_PADDLE_PRICE_MSP] = "msp"


_build_price_map()


# ── Paddle REST helper ────────────────────────────────────────────────────────

def _paddle_request(method: str, path: str, body: dict | None = None) -> dict:
    url  = f"{_API_BASE}{path}"
    data = json.dumps(body).encode() if body else None
    req  = urllib.request.Request(
        url, data=data,
        headers={
            "Authorization": f"Bearer {_PADDLE_API_KEY}",
            "Content-Type":  "application/json",
        },
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body_text = exc.read().decode(errors="replace")
        raise RuntimeError(f"Paddle API {exc.code}: {body_text}") from exc


# ── PaddleBilling ─────────────────────────────────────────────────────────────

class PaddleBilling:
    """Manages Paddle Billing subscriptions and plan state per tenant."""

    def __init__(self, db_path: Path = _DB_PATH) -> None:
        self._enabled = bool(_PADDLE_API_KEY)
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
                    tenant_id              TEXT PRIMARY KEY,
                    paddle_customer_id     TEXT,
                    paddle_subscription_id TEXT,
                    plan                   TEXT NOT NULL DEFAULT 'free',
                    status                 TEXT NOT NULL DEFAULT 'active',
                    current_period_end     TEXT,
                    updated_at             TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_subs_customer
                    ON subscriptions(paddle_customer_id);
            """)
            self._conn.commit()

    # ── Plan / quota queries ──────────────────────────────────────────────────

    def get_plan(self, tenant_id: str) -> str:
        row = self._conn.execute(
            "SELECT plan, status FROM subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()
        if row is None:
            return "free"
        if row["status"] not in ("active", "trialing"):
            return "free"
        return row["plan"]

    def get_quota(self, tenant_id: str) -> int | None:
        return PLAN_QUOTAS.get(self.get_plan(tenant_id), PLAN_QUOTAS["free"])

    def get_status(self, tenant_id: str) -> dict:
        row = self._conn.execute(
            "SELECT * FROM subscriptions WHERE tenant_id=?", (tenant_id,)
        ).fetchone()
        plan = self.get_plan(tenant_id)
        return {
            "tenant_id":   tenant_id,
            "plan":        plan,
            "quota":       PLAN_QUOTAS.get(plan),
            "status":      row["status"] if row else "free",
            "period_end":  row["current_period_end"] if row else None,
            "customer_id": row["paddle_customer_id"] if row else None,
        }

    # ── Paddle Checkout ───────────────────────────────────────────────────────

    def create_checkout_session(
        self,
        tenant_id:      str,
        plan:           str,
        success_url:    str,
        cancel_url:     str,
        customer_email: str | None = None,
    ) -> str:
        """Create a Paddle transaction and return the hosted checkout URL."""
        if not self._enabled:
            raise RuntimeError("Paddle not configured (PADDLE_API_KEY missing).")
        if plan not in ("pro", "msp"):
            raise ValueError(f"Invalid plan {plan!r}. Choose 'pro' or 'msp'.")
        price_id = _PADDLE_PRICE_PRO if plan == "pro" else _PADDLE_PRICE_MSP
        if not price_id:
            raise RuntimeError(
                f"PADDLE_PRICE_{plan.upper()} env var not set. "
                "Create a recurring price in the Paddle Dashboard and set it here."
            )

        body: dict = {
            "items": [{"price_id": price_id, "quantity": 1}],
            "checkout": {"url": success_url},
            "custom_data": {"tenant_id": tenant_id},
        }
        if customer_email:
            body["customer"] = {"email": customer_email}

        resp = _paddle_request("POST", "/transactions", body)
        checkout_url = (resp.get("data") or {}).get("checkout", {}).get("url", "")
        if not checkout_url:
            raise RuntimeError("Paddle did not return a checkout URL.")

        log.info("Paddle: checkout created tenant=%s plan=%s.", tenant_id, plan)
        return checkout_url

    # ── Customer Portal ───────────────────────────────────────────────────────

    def get_portal_url(self, tenant_id: str) -> str:
        """
        Return a Paddle customer portal URL for self-serve subscription management.
        Falls back to the generic Paddle customer portal if no customer record exists.
        """
        row = self._conn.execute(
            "SELECT paddle_customer_id FROM subscriptions WHERE tenant_id=?",
            (tenant_id,),
        ).fetchone()

        if self._enabled and row and row["paddle_customer_id"]:
            try:
                resp = _paddle_request(
                    "POST",
                    f"/customers/{row['paddle_customer_id']}/auth-token",
                )
                token = (resp.get("data") or {}).get("customer_auth_token", "")
                if token:
                    base = (
                        "https://sandbox-customer.paddle.com"
                        if _PADDLE_SANDBOX
                        else "https://customer.paddle.com"
                    )
                    return f"{base}?customerAuthToken={token}"
            except RuntimeError:
                pass

        # Fallback: generic self-serve portal
        return (
            "https://sandbox-customer.paddle.com"
            if _PADDLE_SANDBOX
            else "https://customer.paddle.com"
        )

    # ── Webhook handler ───────────────────────────────────────────────────────

    def handle_webhook(self, payload: bytes, signature_header: str) -> str:
        """
        Validate and process a Paddle webhook event.

        Paddle-Signature header format: ts=<timestamp>;h1=<hex_hmac>
        Returns the event_type string.
        Raises ValueError on invalid signature.
        """
        if _PADDLE_WEBHOOK_SECRET and signature_header:
            parts    = dict(p.split("=", 1) for p in signature_header.split(";") if "=" in p)
            ts       = parts.get("ts", "")
            h1       = parts.get("h1", "")
            signed   = f"{ts}:{payload.decode()}"
            expected = hmac.new(
                _PADDLE_WEBHOOK_SECRET.encode(),
                signed.encode(),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(expected, h1):
                raise ValueError("Invalid Paddle webhook signature.")

        event  = json.loads(payload)
        etype  = event.get("event_type", "")
        data   = event.get("data", {})

        if etype == "transaction.completed":
            self._on_transaction_completed(data)
        elif etype in ("subscription.created", "subscription.updated"):
            self._on_subscription_updated(data)
        elif etype == "subscription.canceled":
            self._on_subscription_canceled(data)
        elif etype in ("subscription.past_due", "transaction.payment_failed"):
            sub_id = data.get("id", "")
            if sub_id:
                self._set_status_by_sub(sub_id, "past_due")

        log.info("Paddle webhook: %s processed.", etype)
        return etype

    # ── Webhook sub-handlers ──────────────────────────────────────────────────

    def _on_transaction_completed(self, txn: dict) -> None:
        custom_data = txn.get("custom_data") or {}
        tenant_id   = custom_data.get("tenant_id", "")
        if not tenant_id:
            log.warning("Paddle: transaction.completed missing tenant_id in custom_data.")
            return
        customer_id = txn.get("customer_id", "")
        sub_id      = txn.get("subscription_id", "")
        items       = txn.get("items", [])
        price_id    = (items[0].get("price") or {}).get("id", "") if items else ""
        plan        = _PRICE_TO_PLAN.get(price_id, "pro")
        self._upsert(tenant_id, customer_id, sub_id, plan, "active", None)
        log.info("Paddle: tenant %s activated plan=%s.", tenant_id, plan)

    def _on_subscription_updated(self, sub: dict) -> None:
        custom_data = sub.get("custom_data") or {}
        tenant_id   = custom_data.get("tenant_id", "")
        if not tenant_id:
            cid = sub.get("customer_id", "")
            row = self._conn.execute(
                "SELECT tenant_id FROM subscriptions WHERE paddle_customer_id=?", (cid,)
            ).fetchone()
            tenant_id = row["tenant_id"] if row else ""
        if not tenant_id:
            return
        items      = sub.get("items", [])
        price_id   = (items[0].get("price") or {}).get("id", "") if items else ""
        plan       = _PRICE_TO_PLAN.get(price_id, "pro")
        status     = sub.get("status", "active")
        period_end = (sub.get("current_billing_period") or {}).get("ends_at")
        self._upsert(
            tenant_id, sub.get("customer_id", ""), sub.get("id", ""),
            plan, status, period_end,
        )

    def _on_subscription_canceled(self, sub: dict) -> None:
        sub_id = sub.get("id", "")
        with self._lock:
            self._conn.execute(
                "UPDATE subscriptions SET plan='free', status='cancelled', updated_at=?"
                " WHERE paddle_subscription_id=?",
                (datetime.now(UTC).isoformat(), sub_id),
            )
            self._conn.commit()

    def _set_status_by_sub(self, sub_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE subscriptions SET status=?, updated_at=?"
                " WHERE paddle_subscription_id=?",
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
        period_end:  str | None,
    ) -> None:
        now = datetime.now(UTC).isoformat()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO subscriptions
                    (tenant_id, paddle_customer_id, paddle_subscription_id,
                     plan, status, current_period_end, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id) DO UPDATE SET
                    paddle_customer_id     = excluded.paddle_customer_id,
                    paddle_subscription_id = excluded.paddle_subscription_id,
                    plan                   = excluded.plan,
                    status                 = excluded.status,
                    current_period_end     = excluded.current_period_end,
                    updated_at             = excluded.updated_at
                """,
                (tenant_id, customer_id, sub_id, plan, status, period_end, now),
            )
            self._conn.commit()

    def close(self) -> None:
        self._conn.close()


# ── Module-level singleton ────────────────────────────────────────────────────

_instance:      PaddleBilling | None = None
_instance_lock: threading.Lock       = threading.Lock()


def get_paddle_billing() -> PaddleBilling:
    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = PaddleBilling()
    return _instance
