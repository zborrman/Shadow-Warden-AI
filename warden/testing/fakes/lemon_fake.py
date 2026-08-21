"""
warden/testing/fakes/lemon_fake.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FakeLemonSqueezy — a stand-in for the Lemon Squeezy merchant of record.

Why this exists
───────────────
The fiat rail (P1b) is gated on a registered legal entity, because Lemon Squeezy
is a merchant of record. `warden/lemon_billing.py` is written and idle: checkout
creation and webhook handling are complete, production simply has no keys. That
would leave the entire billing path unexercised until a company exists.

This fake removes the dependency for **development only**. It answers the two
seams the real provider owns:

  * ``request()``  replaces ``lemon_billing._ls_request`` — the module's only
    outbound HTTP call.
  * ``emit()``     produces a webhook envelope signed with the same HMAC-SHA256
    scheme ``LemonBilling.handle_webhook`` verifies, so the signature path is
    exercised for real rather than bypassed.

What it does NOT prove
──────────────────────
The wire format. Event names, JSON:API shape and retry behaviour are copied from
the provider's documentation, and a fake can only ever agree with the developer
who wrote it — the failure mode that let clearing settle every trade at $0.00
with tests that agreed. Only Lemon Squeezy's own **test mode** (real API, real
webhooks, test cards — an account, no company) validates the wire, and only live
keys validate the rail. Keep the capability matrix row at ``SIMULATED`` until
then: this fake proves the plumbing, never the money.

Safety
──────
Construction refuses outright in a production environment, and every artifact it
issues carries ``test_mode: true`` (a real Lemon Squeezy field) plus a
``_fake_provider`` marker in ``meta``, so no row this produces can later be read
as revenue.

Usage
─────
    with FakeContext() as ctx:
        billing = LemonBilling(db_path=tmp_path / "lemon.db")   # inside the context
        url = billing.create_checkout_session("tenant-1", "pro", "https://ok", "https://no")
        ctx.lemon.deliver(billing, "subscription_created", tenant_id="tenant-1", plan="pro")
        assert billing.get_plan("tenant-1") == "pro"

``LemonBilling`` snapshots ``_LS_API_KEY`` into ``self._enabled`` at construction,
so it must be constructed **inside** the context, not before it.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

#: Webhook signing secret the fake uses. Patched over the module global by
#: FakeContext so `handle_webhook` verifies against this same value.
FAKE_WEBHOOK_SECRET = "fake-lemon-webhook-secret"

FAKE_API_KEY = "fake-lemon-api-key"
FAKE_STORE_ID = "fake-store-1"

#: plan → variant id. Mirrors the LEMONSQUEEZY_VARIANT_<PLAN> env vars, whose
#: values are opaque numeric strings in the real dashboard.
FAKE_VARIANTS: dict[str, str] = {
    "trial": "900000",
    "individual": "900001",
    "community_business": "900002",
    "pro": "900003",
    "enterprise": "900004",
}

_VARIANT_TO_PLAN: dict[str, str] = {v: k for k, v in FAKE_VARIANTS.items()}

#: Stamped on every artifact this fake issues. Not overridable — see `emit()`.
_FAKE_PROVIDER = "FakeLemonSqueezy"


class FakeLemonSqueezyError(RuntimeError):
    """Raised for a call the fake does not model, so gaps are loud."""


class FakeLemonSqueezy:
    """In-memory Lemon Squeezy double: REST responses plus signed webhooks."""

    def __init__(self, webhook_secret: str = FAKE_WEBHOOK_SECRET) -> None:
        self._assert_not_production()
        self.webhook_secret = webhook_secret
        #: every REST call, as (method, path, body) — assert against these
        self.calls: list[tuple[str, str, dict | None]] = []
        #: checkouts issued, keyed by checkout id
        self.checkouts: dict[str, dict] = {}
        #: every webhook envelope emitted, in order
        self.emitted: list[dict] = []
        self._seq = 0

    # ── Safety ───────────────────────────────────────────────────────────────

    @staticmethod
    def _assert_not_production() -> None:
        """A billing double must never be constructible in production.

        Checked at construction rather than at use: the object existing at all
        in a production process is the defect, and failing at the seam would
        leave a half-built state behind.
        """
        env = (os.getenv("WARDEN_ENV") or os.getenv("ENV") or "").strip().lower()
        if env in ("production", "prod"):
            raise FakeLemonSqueezyError(
                "FakeLemonSqueezy must not be constructed in production "
                f"(WARDEN_ENV={env!r}). It grants plans and feature flags."
            )

    # ── REST seam — replaces lemon_billing._ls_request ────────────────────────

    def request(self, method: str, path: str, body: dict | None = None) -> dict:
        """Answer a Lemon Squeezy REST call in the JSON:API shape the caller parses."""
        self.calls.append((method, path, body))

        if method == "POST" and path == "/checkouts":
            return self._create_checkout(body or {})

        raise FakeLemonSqueezyError(
            f"FakeLemonSqueezy does not model {method} {path}. "
            "Add it here rather than letting the call succeed silently."
        )

    def _create_checkout(self, body: dict) -> dict:
        attrs = (body.get("data") or {}).get("attributes") or {}
        rels = (body.get("data") or {}).get("relationships") or {}
        variant_id = str(((rels.get("variant") or {}).get("data") or {}).get("id", ""))
        custom = (attrs.get("checkout_data") or {}).get("custom") or {}

        self._seq += 1
        checkout_id = f"fake-checkout-{self._seq}"
        record = {
            "id": checkout_id,
            "variant_id": variant_id,
            "plan": _VARIANT_TO_PLAN.get(variant_id, "unknown"),
            "tenant_id": custom.get("tenant_id", ""),
            "agent_id": custom.get("agent_id", ""),
            "email": (attrs.get("checkout_data") or {}).get("email", ""),
            "redirect_url": (attrs.get("product_options") or {}).get("redirect_url", ""),
        }
        self.checkouts[checkout_id] = record

        return {
            "data": {
                "type": "checkouts",
                "id": checkout_id,
                "attributes": {
                    # The host is deliberately not lemonsqueezy.com: a URL from
                    # this fake must never be mistaken for a payable checkout.
                    "url": f"https://fake-lemon.invalid/checkout/{checkout_id}",
                    "test_mode": True,
                    # Provenance travels with the artifact, not just with the
                    # webhook: a checkout response that outlives this process —
                    # logged, cached, pasted into an issue — must still say what
                    # produced it.
                    "_fake_provider": _FAKE_PROVIDER,
                    "store_id": FAKE_STORE_ID,
                    "variant_id": variant_id,
                },
            }
        }

    # ── Webhook seam ─────────────────────────────────────────────────────────

    def emit(
        self,
        event_name: str,
        *,
        tenant_id: str = "",
        plan: str = "pro",
        sub_id: str = "fake-sub-1",
        customer_id: str = "fake-customer-1",
        status: str | None = None,
        renews_at: str | None = None,
        event_id: str | None = None,
        sub_item_id: str = "fake-sub-item-1",
        attributes: dict[str, Any] | None = None,
    ) -> tuple[bytes, str]:
        """Build one webhook envelope and its ``X-Signature`` header.

        Returns ``(payload_bytes, signature_hex)``. The bytes are what must be
        handed to ``handle_webhook`` — signing is over the raw body, so a
        re-serialised dict would verify differently.
        """
        variant_id = FAKE_VARIANTS.get(plan, FAKE_VARIANTS["pro"])
        now = datetime.now(UTC)
        attrs: dict[str, Any] = {
            "customer_id": customer_id,
            "variant_id": variant_id,
            "status": status or ("on_trial" if "trial" in event_name else "active"),
            "renews_at": renews_at or (now + timedelta(days=30)).isoformat(),
            "first_subscription_item": {"id": sub_item_id},
            # Real Lemon Squeezy field. Doubles as the honesty marker: nothing
            # this fake issues can be read as a live payment.
            "test_mode": True,
        }
        if event_name == "subscription_trial_started":
            attrs["trial_ends_at"] = (now + timedelta(days=14)).isoformat()
        if event_name == "order_created":
            attrs["first_order_item"] = {"variant_id": variant_id}
        if attributes:
            attrs.update(attributes)
        # Applied last, so a caller-supplied `attributes` override cannot strip
        # the provenance. A test that needs to simulate a live-mode payload is
        # asking for a different fake, not for this one to lie about itself.
        attrs["test_mode"] = True
        attrs["_fake_provider"] = _FAKE_PROVIDER

        envelope = {
            "meta": {
                "event_name": event_name,
                "event_id": event_id or str(uuid.uuid4()),
                "custom_data": {"tenant_id": tenant_id} if tenant_id else {},
                "test_mode": True,
                "_fake_provider": _FAKE_PROVIDER,
            },
            "data": {
                "type": "subscriptions" if event_name.startswith("subscription") else "orders",
                "id": sub_id,
                "attributes": attrs,
            },
        }
        self.emitted.append(envelope)

        payload = json.dumps(envelope).encode()
        return payload, self.sign(payload)

    def sign(self, payload: bytes) -> str:
        """HMAC-SHA256 hex digest over the raw body — the scheme LS uses."""
        return hmac.new(self.webhook_secret.encode(), payload, hashlib.sha256).hexdigest()

    def deliver(self, billing: Any, event_name: str, **kwargs: Any) -> str:
        """Emit an event and hand it to ``LemonBilling.handle_webhook``."""
        payload, signature = self.emit(event_name, **kwargs)
        return str(billing.handle_webhook(payload, signature))

    # ── Assertions helpers ───────────────────────────────────────────────────

    def checkout_count(self) -> int:
        return len(self.checkouts)

    def events_named(self, event_name: str) -> list[dict]:
        return [e for e in self.emitted if e["meta"]["event_name"] == event_name]

    def clear(self) -> None:
        self.calls.clear()
        self.checkouts.clear()
        self.emitted.clear()
