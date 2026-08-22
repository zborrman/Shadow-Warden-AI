"""
warden/tests/test_lemon_fake_rail.py
────────────────────────────────────
The fiat rail end to end against `FakeLemonSqueezy`, with no Lemon Squeezy
account and no legal entity.

What these tests are for: P1b is gated on a registered company, because Lemon
Squeezy is a merchant of record. `lemon_billing.py` is complete and idle, so the
whole billing path — checkout → signed webhook → plan → feature flags — would
otherwise stay unexercised until that company exists.

What they are NOT: proof the rail works. The envelope shapes come from the
provider's documentation, and a fake can only agree with whoever wrote it. Only
Lemon Squeezy's own test mode validates the wire format, and only live keys
validate the money. See `warden/testing/fakes/lemon_fake.py`.
"""
from __future__ import annotations

import pytest

from warden.testing.context import FakeContext
from warden.testing.fakes.lemon_fake import (
    FAKE_VARIANTS,
    FakeLemonSqueezy,
    FakeLemonSqueezyError,
)


@pytest.fixture()
def rail(tmp_path):
    """A FakeContext with a LemonBilling built inside it.

    Construction order matters: `LemonBilling.__init__` snapshots `_LS_API_KEY`
    into `self._enabled`, so an instance created before the context would be
    permanently disabled.
    """
    from warden.lemon_billing import LemonBilling
    with FakeContext() as ctx:
        yield ctx, LemonBilling(db_path=tmp_path / "fake_rail.db")


# ── Checkout ──────────────────────────────────────────────────────────────────

class TestCheckout:
    def test_checkout_returns_a_url_and_records_the_intent(self, rail):
        ctx, billing = rail
        url = billing.create_checkout_session(
            "tenant-1", "pro", "https://ok.example", "https://no.example",
            customer_email="buyer@example.com",
        )
        assert url.startswith("https://fake-lemon.invalid/checkout/")
        assert ctx.lemon.checkout_count() == 1
        record = next(iter(ctx.lemon.checkouts.values()))
        assert record["tenant_id"] == "tenant-1"
        assert record["plan"] == "pro"
        assert record["email"] == "buyer@example.com"
        assert record["redirect_url"] == "https://ok.example"

    def test_checkout_url_is_never_a_lemonsqueezy_host(self, rail):
        """A URL from the fake must not be mistakable for a payable checkout."""
        _ctx, billing = rail
        url = billing.create_checkout_session(
            "tenant-1", "individual", "https://ok.example", "https://no.example"
        )
        assert "lemonsqueezy.com" not in url

    def test_unconfigured_plan_is_rejected(self, rail):
        _ctx, billing = rail
        with pytest.raises(ValueError):
            billing.create_checkout_session(
                "tenant-1", "no-such-plan", "https://ok.example", "https://no.example"
            )


# ── Subscription lifecycle ────────────────────────────────────────────────────

class TestLifecycle:
    def test_created_activates_the_plan(self, rail):
        ctx, billing = rail
        event = ctx.lemon.deliver(
            billing, "subscription_created", tenant_id="t-1", plan="pro"
        )
        assert event == "subscription_created"
        assert billing.get_plan("t-1") == "pro"
        assert billing.get_status("t-1")["status"] == "active"

    def test_plan_drives_feature_flags(self, rail):
        ctx, billing = rail
        ctx.lemon.deliver(billing, "subscription_created", tenant_id="t-pro", plan="pro")
        flags = billing.get_feature_flags("t-pro")
        assert flags["sova_agent"] is True
        assert flags["marketplace_node"] is True
        assert flags["post_quantum_cryptography"] is False

    def test_enterprise_unlocks_pqc(self, rail):
        ctx, billing = rail
        ctx.lemon.deliver(
            billing, "subscription_created", tenant_id="t-ent", plan="enterprise"
        )
        assert billing.get_feature_flags("t-ent")["post_quantum_cryptography"] is True

    def test_cancellation_downgrades_and_revokes(self, rail):
        ctx, billing = rail
        ctx.lemon.deliver(
            billing, "subscription_created", tenant_id="t-2", plan="pro", sub_id="sub-2"
        )
        ctx.lemon.deliver(billing, "subscription_cancelled", sub_id="sub-2")
        assert billing.get_plan("t-2") == "starter"
        assert billing.get_feature_flags("t-2")["sova_agent"] is False

    def test_trial_starts_then_expires_to_starter(self, rail):
        ctx, billing = rail
        ctx.lemon.deliver(
            billing, "subscription_trial_started",
            tenant_id="t-3", plan="trial", sub_id="sub-3",
        )
        assert billing.get_status("t-3")["status"] == "on_trial"
        ctx.lemon.deliver(billing, "subscription_trial_ended", sub_id="sub-3")
        assert billing.get_plan("t-3") == "starter"

    def test_payment_failure_marks_past_due(self, rail):
        ctx, billing = rail
        ctx.lemon.deliver(
            billing, "subscription_created", tenant_id="t-4", plan="pro", sub_id="sub-4"
        )
        ctx.lemon.deliver(billing, "subscription_payment_failed", sub_id="sub-4")
        status = billing.get_status("t-4")
        assert status["status"] == "past_due"
        # past_due is not an entitled state
        assert billing.get_plan("t-4") == "starter"

    def test_one_time_order_activates_a_plan(self, rail):
        ctx, billing = rail
        ctx.lemon.deliver(
            billing, "order_created", tenant_id="t-5", plan="community_business"
        )
        assert billing.get_plan("t-5") == "community_business"


# ── Signature and replay ──────────────────────────────────────────────────────

class TestWebhookSecurity:
    def test_signature_is_verified_not_bypassed(self, rail):
        """The fake signs with the same secret `handle_webhook` checks."""
        ctx, billing = rail
        payload, signature = ctx.lemon.emit(
            "subscription_created", tenant_id="t-6", plan="pro"
        )
        assert billing.handle_webhook(payload, signature) == "subscription_created"

    def test_forged_signature_is_rejected(self, rail):
        ctx, billing = rail
        payload, _sig = ctx.lemon.emit("subscription_created", tenant_id="t-7", plan="pro")
        with pytest.raises(ValueError):
            billing.handle_webhook(payload, "0" * 64)
        assert billing.get_plan("t-7") == "starter"

    def test_missing_signature_is_rejected(self, rail):
        ctx, billing = rail
        payload, _sig = ctx.lemon.emit("subscription_created", tenant_id="t-8", plan="pro")
        with pytest.raises(ValueError):
            billing.handle_webhook(payload, "")
        assert billing.get_plan("t-8") == "starter"

    def test_tampered_payload_is_rejected(self, rail):
        """Signing is over raw bytes, so any edit invalidates the digest."""
        ctx, billing = rail
        payload, signature = ctx.lemon.emit(
            "subscription_created", tenant_id="t-9", plan="individual"
        )
        # Upgrade the plan in flight: the variant id is what maps to a tier.
        tampered = payload.replace(
            FAKE_VARIANTS["individual"].encode(), FAKE_VARIANTS["enterprise"].encode()
        )
        assert tampered != payload
        with pytest.raises(ValueError):
            billing.handle_webhook(tampered, signature)

    def test_replayed_event_id_is_processed_once(self, rail):
        """Lemon Squeezy retries on timeout; the second delivery must be inert."""
        ctx, billing = rail
        payload, signature = ctx.lemon.emit(
            "subscription_created", tenant_id="t-10", plan="pro",
            sub_id="sub-10", event_id="fixed-event-id",
        )
        billing.handle_webhook(payload, signature)
        # Move the tenant off the plan through the public path — a second, valid
        # signed event — then replay the original. Asserting through the webhook
        # contract rather than through storage internals means this test still
        # fails if idempotency breaks after a refactor of the tables.
        ctx.lemon.deliver(billing, "subscription_cancelled", sub_id="sub-10")
        assert billing.get_plan("t-10") == "starter"
        billing.handle_webhook(payload, signature)
        assert billing.get_plan("t-10") == "starter", (
            "replayed event re-applied itself — idempotency is not holding"
        )


# ── The fake's own guarantees ─────────────────────────────────────────────────

class TestFakeGuarantees:
    def test_unmodelled_rest_call_is_loud(self):
        fake = FakeLemonSqueezy()
        with pytest.raises(FakeLemonSqueezyError):
            fake.request("GET", "/subscriptions/1")

    def test_refuses_to_exist_in_production(self, monkeypatch):
        monkeypatch.setenv("WARDEN_ENV", "production")
        with pytest.raises(FakeLemonSqueezyError):
            FakeLemonSqueezy()

    def test_every_artifact_is_marked_test_mode(self, rail):
        ctx, billing = rail
        billing.create_checkout_session(
            "t-11", "pro", "https://ok.example", "https://no.example"
        )
        ctx.lemon.deliver(billing, "subscription_created", tenant_id="t-11", plan="pro")
        checkout = ctx.lemon.request("POST", "/checkouts", {"data": {}})
        assert checkout["data"]["attributes"]["test_mode"] is True
        assert checkout["data"]["attributes"]["_fake_provider"] == "FakeLemonSqueezy"
        envelope = ctx.lemon.events_named("subscription_created")[0]
        assert envelope["meta"]["test_mode"] is True
        assert envelope["meta"]["_fake_provider"] == "FakeLemonSqueezy"
        assert envelope["data"]["attributes"]["test_mode"] is True
        assert envelope["data"]["attributes"]["_fake_provider"] == "FakeLemonSqueezy"

    def test_provenance_survives_a_caller_override(self, rail):
        """A caller must not be able to dress a fake payload as a live one."""
        ctx, _billing = rail
        _payload, _sig = ctx.lemon.emit(
            "subscription_created",
            tenant_id="t-13",
            plan="pro",
            attributes={"test_mode": False, "_fake_provider": "lemonsqueezy"},
        )
        attrs = ctx.lemon.events_named("subscription_created")[0]["data"]["attributes"]
        assert attrs["test_mode"] is True
        assert attrs["_fake_provider"] == "FakeLemonSqueezy"

    def test_no_network_call_is_made(self, rail):
        """The REST seam is replaced, so nothing reaches urllib."""
        ctx, billing = rail
        billing.create_checkout_session(
            "t-12", "pro", "https://ok.example", "https://no.example"
        )
        assert ctx.lemon.calls == [
            ("POST", "/checkouts", ctx.lemon.calls[0][2])
        ]
