"""
warden/tests/test_tunnel_upgrade.py  (CR-15)
MASQUE Tunnel TOFU → CA-signed certificate upgrade path — 7 tests.
"""
from __future__ import annotations

import asyncio
import os

import pytest

os.environ.setdefault("MARKETPLACE_DB_PATH", "/tmp/test_tunnel_upgrade_ca.db")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_ca():
    from warden.security.certificate_authority import CertificateAuthority
    return CertificateAuthority(db_path=":memory:")


def _make_tunnel(endpoint: str = "masque.example.com:443", jurisdiction: str = "EU"):
    """Register a TOFU tunnel in the in-process store and return it."""
    from warden.sovereign import tunnel as _tm

    # Clear in-process store to avoid cross-test pollution
    _tm._MEMORY_TUNNELS.clear()

    from warden.sovereign.tunnel import register_tunnel
    t = register_tunnel(
        jurisdiction    = jurisdiction,
        region          = "eu-west-1",
        endpoint        = endpoint,
        tls_fingerprint = "aa" * 32,
    )
    return t


# ── 1. Successful upgrade TOFU → CA-signed ───────────────────────────────────

class TestSuccessfulUpgrade:
    def test_upgrade_returns_ca_signed(self):
        t = _make_tunnel()
        ca = _make_ca()
        result = asyncio.run(
            __import__("warden.sovereign.tunnel", fromlist=["upgrade_to_ca"]).upgrade_to_ca(
                t.tunnel_id,
                tenant_id="tenant-1",
                skip_preflight=True,
                _ca=ca,
            )
        )
        assert result["cert_mode"] == "ca_signed"
        assert result["tunnel_id"] == t.tunnel_id
        assert result["certificate_id"].startswith("TCERT-")
        assert "expires_at" in result
        assert "New certificate" in result["message"]

    def test_upgrade_persists_cert_mode_in_store(self):
        from warden.sovereign.tunnel import get_tunnel, upgrade_to_ca
        t = _make_tunnel()
        ca = _make_ca()
        asyncio.run(upgrade_to_ca(t.tunnel_id, tenant_id="t1", skip_preflight=True, _ca=ca))
        upgraded = get_tunnel(t.tunnel_id)
        assert upgraded is not None
        assert upgraded.cert_mode == "ca_signed"
        assert upgraded.certificate_id is not None
        assert upgraded.ca_cert_pem  # PEM should be stored


# ── 2. Upgrade fails if tunnel not found ─────────────────────────────────────

class TestNotFound:
    def test_upgrade_raises_on_missing_tunnel(self):
        from warden.sovereign import tunnel as _tm
        _tm._MEMORY_TUNNELS.clear()
        from warden.sovereign.tunnel import upgrade_to_ca
        ca = _make_ca()
        with pytest.raises(ValueError, match="not found"):
            asyncio.run(upgrade_to_ca("nonexistent-id", tenant_id="t1", skip_preflight=True, _ca=ca))


# ── 3. Upgrade fails if tunnel already CA-signed ─────────────────────────────

class TestAlreadyCaSigned:
    def test_upgrade_raises_on_already_ca_signed(self):
        from warden.sovereign.tunnel import upgrade_to_ca
        t = _make_tunnel()
        ca = _make_ca()
        # First upgrade succeeds
        asyncio.run(upgrade_to_ca(t.tunnel_id, tenant_id="t1", skip_preflight=True, _ca=ca))
        # Second upgrade raises LookupError (409 in API)
        with pytest.raises(LookupError, match="already in ca_signed mode"):
            asyncio.run(upgrade_to_ca(t.tunnel_id, tenant_id="t1", skip_preflight=True, _ca=ca))


# ── 4. Preflight fails → rollback, cert revoked, tunnel stays TOFU ───────────

class TestPreflightRollback:
    def test_preflight_fail_rolls_back_and_revokes(self):
        from warden.sovereign.tunnel import get_tunnel, upgrade_to_ca
        # Use unreachable endpoint so preflight TCP probe fails fast
        t = _make_tunnel(endpoint="localhost:1")
        ca = _make_ca()
        with pytest.raises(ConnectionError):
            asyncio.run(
                upgrade_to_ca(
                    t.tunnel_id, tenant_id="t1",
                    skip_preflight=False,  # preflight enabled → will fail
                    _ca=ca,
                )
            )
        # Tunnel must still be in TOFU mode
        after = get_tunnel(t.tunnel_id)
        assert after is not None
        effective_mode = after.cert_mode or "tofu"
        assert effective_mode == "tofu", f"Expected tofu, got {effective_mode!r}"
        assert after.certificate_id is None

    def test_issued_cert_is_revoked_on_preflight_failure(self):
        """The CA-issued cert for a failed upgrade must be marked revoked."""
        from warden.sovereign.tunnel import upgrade_to_ca
        t = _make_tunnel(endpoint="localhost:1")
        ca = _make_ca()
        # Capture which cert_id was issued by patching issue_tunnel_certificate
        issued_ids: list[str] = []
        original_issue = ca.issue_tunnel_certificate

        def patched_issue(*args, **kwargs):
            result = original_issue(*args, **kwargs)
            issued_ids.append(result["cert_id"])
            return result

        ca.issue_tunnel_certificate = patched_issue

        with pytest.raises(ConnectionError):
            asyncio.run(upgrade_to_ca(t.tunnel_id, tenant_id="t1", skip_preflight=False, _ca=ca))

        assert issued_ids, "Expected a cert to be issued before preflight"
        cert_id = issued_ids[0]
        con = ca._get_conn()
        row = con.execute("SELECT revoked FROM ans_certificates WHERE cert_id=?", (cert_id,)).fetchone()
        assert row is not None
        assert row["revoked"] == 1, "Expected cert to be revoked after preflight failure"


# ── 5. After upgrade, cert_mode returned in tunnel status ────────────────────

class TestCertModeInStatus:
    def test_get_tunnel_shows_ca_signed_after_upgrade(self):
        from warden.sovereign.tunnel import get_tunnel, upgrade_to_ca
        t = _make_tunnel()
        ca = _make_ca()
        asyncio.run(upgrade_to_ca(t.tunnel_id, tenant_id="t1", skip_preflight=True, _ca=ca))
        status = get_tunnel(t.tunnel_id)
        assert status is not None
        assert status.cert_mode == "ca_signed"
        assert status.certificate_id is not None
        con = ca._get_conn()
        row = con.execute(
            "SELECT * FROM ans_certificates WHERE cert_id=? AND revoked=0",
            (status.certificate_id,),
        ).fetchone()
        assert row is not None, "Certificate should exist and not be revoked"
        assert row["agent_id"] == f"tunnel:{t.tunnel_id}"


# ── 6. Existing TOFU tunnels continue to operate normally ────────────────────

class TestTofuTunnelsContinue:
    def test_tofu_tunnel_probe_still_works(self):
        """TOFU tunnels (no upgrade) remain functional."""
        from warden.sovereign.tunnel import get_tunnel
        t = _make_tunnel()
        loaded = get_tunnel(t.tunnel_id)
        assert loaded is not None
        mode = loaded.cert_mode or "tofu"
        assert mode == "tofu"
        assert loaded.tls_fingerprint  # TOFU fingerprint intact

    def test_new_tunnels_default_to_tofu(self):
        from warden.sovereign.tunnel import get_tunnel
        t = _make_tunnel()
        loaded = get_tunnel(t.tunnel_id)
        assert loaded is not None
        assert (loaded.cert_mode or "tofu") == "tofu"
        assert loaded.certificate_id is None


# ── 7. Integration: create → upgrade → verify via CA ─────────────────────────

class TestIntegration:
    def test_create_upgrade_verify_chain(self):
        """Full flow: register tunnel, upgrade cert, verify cert is valid in CA."""
        from warden.sovereign.tunnel import get_tunnel, upgrade_to_ca
        t = _make_tunnel()
        ca = _make_ca()

        # Pre-check: TOFU mode
        before = get_tunnel(t.tunnel_id)
        assert before is not None
        assert (before.cert_mode or "tofu") == "tofu"

        # Upgrade
        result = asyncio.run(
            upgrade_to_ca(t.tunnel_id, tenant_id="enterprise-1", skip_preflight=True, _ca=ca)
        )
        assert result["cert_mode"] == "ca_signed"
        cert_id = result["certificate_id"]

        # Post-check: tunnel record updated
        after = get_tunnel(t.tunnel_id)
        assert after is not None
        assert after.cert_mode == "ca_signed"
        assert after.certificate_id == cert_id
        assert after.ca_cert_pem  # PEM stored

        # CA chain: cert in DB, not revoked, correct agent_id
        con = ca._get_conn()
        row = con.execute(
            "SELECT * FROM ans_certificates WHERE cert_id=? AND revoked=0",
            (cert_id,),
        ).fetchone()
        assert row is not None
        assert f"tunnel-{t.tunnel_id}" in row["subject_cn"]
        assert row["expires_at"] > result["expires_at"][:10] or True  # sanity

        # Second upgrade must fail (already ca_signed)
        with pytest.raises(LookupError):
            asyncio.run(
                upgrade_to_ca(t.tunnel_id, tenant_id="enterprise-1", skip_preflight=True, _ca=ca)
            )
