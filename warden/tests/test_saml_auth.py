"""
warden/tests/test_saml_auth.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Tests for the SAML authentication helpers in warden/analytics/auth.py.

Streamlit functions are mocked via unittest.mock — no running Streamlit
server needed.  urllib calls are patched to avoid real gateway traffic.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_http_response(body: dict, status: int = 200):
    """Create a fake urllib response context manager."""
    data = json.dumps(body).encode()
    resp = MagicMock()
    resp.read.return_value = data
    resp.__enter__ = lambda s: s
    resp.__exit__  = MagicMock(return_value=False)
    return resp


def _make_http_error(code: int):
    import urllib.error
    return urllib.error.HTTPError(url="", code=code, msg="", hdrs=None, fp=None)  # type: ignore[arg-type]


# ── _exchange_saml_otp ────────────────────────────────────────────────────────

class TestExchangeSamlOtp:

    @patch("streamlit.warning")
    @patch("streamlit.error")
    def test_valid_otp_returns_payload(self, mock_err, mock_warn):
        payload = {
            "access_token": "jwt.token.here",
            "email": "alice@acme.com",
            "name": "Alice",
            "tenant_id": "acme",
        }
        with patch("urllib.request.urlopen", return_value=_make_http_response(payload)):
            from warden.analytics.auth import _exchange_saml_otp
            result = _exchange_saml_otp("valid-otp")
        assert result is not None
        assert result["access_token"] == "jwt.token.here"
        assert result["tenant_id"] == "acme"
        mock_err.assert_not_called()

    @patch("streamlit.warning")
    @patch("streamlit.error")
    def test_invalid_otp_401_returns_none(self, mock_err, mock_warn):
        with patch("urllib.request.urlopen", side_effect=_make_http_error(401)):
            from warden.analytics.auth import _exchange_saml_otp
            result = _exchange_saml_otp("bad-otp")
        assert result is None
        # 401 is a silent failure — no warning shown
        mock_warn.assert_not_called()

    @patch("streamlit.warning")
    @patch("streamlit.error")
    def test_gateway_error_shows_warning(self, mock_err, mock_warn):
        with patch("urllib.request.urlopen", side_effect=_make_http_error(503)):
            from warden.analytics.auth import _exchange_saml_otp
            result = _exchange_saml_otp("otp")
        assert result is None
        mock_warn.assert_called_once()

    @patch("streamlit.warning")
    @patch("streamlit.error")
    def test_network_error_shows_warning(self, mock_err, mock_warn):
        with patch("urllib.request.urlopen", side_effect=ConnectionError("refused")):
            from warden.analytics.auth import _exchange_saml_otp
            result = _exchange_saml_otp("otp")
        assert result is None
        mock_warn.assert_called_once()


# ── _verify_saml_jwt ──────────────────────────────────────────────────────────

class TestVerifySamlJwt:

    def test_valid_jwt_returns_payload(self):
        payload = {"sub": "alice@acme.com", "tid": "acme", "name": "Alice"}
        with patch("urllib.request.urlopen", return_value=_make_http_response(payload)):
            from warden.analytics.auth import _verify_saml_jwt
            result = _verify_saml_jwt("valid.jwt")
        assert result is not None
        assert result["sub"] == "alice@acme.com"

    def test_expired_jwt_returns_none(self):
        with patch("urllib.request.urlopen", side_effect=_make_http_error(401)):
            from warden.analytics.auth import _verify_saml_jwt
            result = _verify_saml_jwt("expired.jwt")
        assert result is None

    def test_network_failure_returns_none(self):
        with patch("urllib.request.urlopen", side_effect=ConnectionError()):
            from warden.analytics.auth import _verify_saml_jwt
            result = _verify_saml_jwt("jwt")
        assert result is None


# ── _saml_session_valid ───────────────────────────────────────────────────────

class TestSamlSessionValid:

    def _make_session_state(self, jwt: str | None = "token") -> dict:
        return {
            "_wa_saml_jwt":    jwt,
            "_wa_saml_user":   "",
            "_wa_saml_tenant": "default",
        }

    @patch("streamlit.session_state", new_callable=lambda: type("SS", (), {"__getitem__": dict.__getitem__, "__setitem__": dict.__setitem__, "get": dict.get}))
    def test_no_jwt_returns_false(self, _):
        state = self._make_session_state(jwt=None)
        with patch("streamlit.session_state", state):
            from warden.analytics.auth import _saml_session_valid
            assert _saml_session_valid() is False

    def test_valid_jwt_returns_true_and_updates_state(self):
        state = self._make_session_state("valid.jwt")
        payload = {"sub": "alice@acme.com", "name": "Alice", "tid": "acme"}
        with patch("streamlit.session_state", state), \
             patch("warden.analytics.auth._verify_saml_jwt", return_value=payload):
            from warden.analytics.auth import _saml_session_valid
            result = _saml_session_valid()
        assert result is True
        assert state["_wa_saml_user"] == "Alice"
        assert state["_wa_saml_tenant"] == "acme"

    def test_expired_jwt_clears_state_returns_false(self):
        state = self._make_session_state("expired.jwt")
        with patch("streamlit.session_state", state), \
             patch("warden.analytics.auth._verify_saml_jwt", return_value=None):
            from warden.analytics.auth import _saml_session_valid
            result = _saml_session_valid()
        assert result is False
        assert state["_wa_saml_jwt"] is None


# ── _try_saml_otp_exchange ────────────────────────────────────────────────────

class TestTrySamlOtpExchange:

    def test_no_token_in_query_params_returns_false(self):
        with patch("streamlit.query_params", {"token": ""}):
            from warden.analytics.auth import _try_saml_otp_exchange
            assert _try_saml_otp_exchange() is False

    def test_empty_query_params_returns_false(self):
        params = {}
        with patch("streamlit.query_params", params):
            from warden.analytics.auth import _try_saml_otp_exchange
            assert _try_saml_otp_exchange() is False

    def test_valid_token_stores_jwt_returns_true(self):
        params = {"token": "valid-otp"}
        state: dict = {
            "_wa_saml_jwt": None, "_wa_saml_user": "", "_wa_saml_tenant": "default"
        }
        payload = {
            "access_token": "real.jwt.token",
            "name": "Alice",
            "email": "alice@acme.com",
            "tenant_id": "acme",
        }
        mock_params = MagicMock()
        mock_params.get.side_effect = lambda k, d="": params.get(k, d)
        mock_params.clear = MagicMock()

        with patch("streamlit.query_params", mock_params), \
             patch("streamlit.session_state", state), \
             patch("warden.analytics.auth._exchange_saml_otp", return_value=payload):
            from warden.analytics.auth import _try_saml_otp_exchange
            result = _try_saml_otp_exchange()

        assert result is True
        assert state["_wa_saml_jwt"] == "real.jwt.token"
        assert state["_wa_saml_user"] == "Alice"
        assert state["_wa_saml_tenant"] == "acme"
        mock_params.clear.assert_called_once()   # URL cleared

    def test_failed_exchange_returns_false(self):
        params = {"token": "bad-otp"}
        state: dict = {"_wa_saml_jwt": None, "_wa_saml_user": "", "_wa_saml_tenant": "default"}
        mock_params = MagicMock()
        mock_params.get.side_effect = lambda k, d="": params.get(k, d)
        mock_params.clear = MagicMock()

        with patch("streamlit.query_params", mock_params), \
             patch("streamlit.session_state", state), \
             patch("warden.analytics.auth._exchange_saml_otp", return_value=None), \
             patch("streamlit.error"):
            from warden.analytics.auth import _try_saml_otp_exchange
            result = _try_saml_otp_exchange()

        assert result is False
        assert state["_wa_saml_jwt"] is None
        mock_params.clear.assert_called_once()   # URL still cleared (no replay)


# ── get_saml_tenant ───────────────────────────────────────────────────────────

class TestGetSamlTenant:

    def test_returns_tenant_from_session(self):
        state = {"_wa_saml_tenant": "acme"}
        with patch("streamlit.session_state", state):
            from warden.analytics.auth import get_saml_tenant
            assert get_saml_tenant() == "acme"

    def test_returns_default_when_not_set(self):
        state: dict = {}
        with patch("streamlit.session_state", state):
            from warden.analytics.auth import get_saml_tenant
            assert get_saml_tenant() == "default"
