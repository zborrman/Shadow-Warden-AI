"""
warden/analytics/auth.py
━━━━━━━━━━━━━━━━━━━━━━━━
Session-based login gate for the Streamlit dashboard.

Features
--------
  • bcrypt password verification (industry standard, timing-safe)
  • Per-session brute-force lockout (configurable attempts + duration)
  • Automatic session expiry (configurable timeout)
  • Constant-time username comparison (no username enumeration)
  • Dev-mode pass-through when DASHBOARD_PASSWORD_HASH is unset
  • CLI helper to generate bcrypt hashes

Configuration (environment variables)
--------------------------------------
  DASHBOARD_USERNAME          Login username          (default: admin)
  DASHBOARD_PASSWORD_HASH     bcrypt hash of password (default: unset → dev mode)
  DASHBOARD_SESSION_MINUTES   Session lifetime        (default: 60)
  DASHBOARD_MAX_ATTEMPTS      Failed attempts before lockout (default: 5)
  DASHBOARD_LOCKOUT_MINUTES   Lockout duration        (default: 15)

Generating a password hash
---------------------------
  python -m warden.analytics.auth
  # Prompts for a password and prints the bcrypt hash to set as
  # DASHBOARD_PASSWORD_HASH in your .env file.

Integration
-----------
  In dashboard.py, call require_auth() immediately after st.set_page_config():

      from warden.analytics.auth import require_auth
      require_auth()   # shows login screen and st.stop() if not authenticated
"""
from __future__ import annotations

import hmac
import os
import time
from typing import Any

import bcrypt
import streamlit as st

# ── Configuration ─────────────────────────────────────────────────────────────

_USERNAME         = os.getenv("DASHBOARD_USERNAME", "admin")
_PASSWORD_HASH    = os.getenv("DASHBOARD_PASSWORD_HASH", "").encode()
_SESSION_MINUTES  = int(os.getenv("DASHBOARD_SESSION_MINUTES", "60"))
_MAX_ATTEMPTS     = int(os.getenv("DASHBOARD_MAX_ATTEMPTS", "5"))
_LOCKOUT_MINUTES  = int(os.getenv("DASHBOARD_LOCKOUT_MINUTES", "15"))

_DEV_MODE = not bool(_PASSWORD_HASH)

# ── SAML / SSO configuration ──────────────────────────────────────────────────

_SAML_ENABLED   = bool(os.getenv("SAML_SP_ENTITY_ID", ""))
_GATEWAY_URL    = os.getenv("GATEWAY_URL", "http://localhost:8001").rstrip("/")
_SSO_LOGIN_URL  = f"{_GATEWAY_URL}/auth/saml/login"
_SSO_SESSION_URL = f"{_GATEWAY_URL}/auth/saml/session"
_SSO_VERIFY_URL  = f"{_GATEWAY_URL}/auth/saml/verify"

# ── Session-state keys (prefixed to avoid collisions with dashboard keys) ─────

_K_AUTH         = "_wa_authenticated"
_K_AUTH_TIME    = "_wa_auth_time"
_K_ATTEMPTS     = "_wa_failed_attempts"
_K_LOCKED_UNTIL = "_wa_locked_until"
_K_USERNAME     = "_wa_username"
# SAML-specific keys
_K_SAML_JWT     = "_wa_saml_jwt"
_K_SAML_USER    = "_wa_saml_user"
_K_SAML_TENANT  = "_wa_saml_tenant"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _init_state() -> None:
    defaults: dict = {
        _K_AUTH:         False,
        _K_AUTH_TIME:    None,
        _K_ATTEMPTS:     0,
        _K_LOCKED_UNTIL: None,
        _K_USERNAME:     "",
        _K_SAML_JWT:     None,
        _K_SAML_USER:    "",
        _K_SAML_TENANT:  "default",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _lockout_status() -> tuple[bool, int]:
    """Return (is_locked, seconds_remaining)."""
    until = st.session_state.get(_K_LOCKED_UNTIL)
    if until is None:
        return False, 0
    remaining = until - time.monotonic()
    if remaining > 0:
        return True, int(remaining)
    # Lockout expired — reset counters
    st.session_state[_K_LOCKED_UNTIL] = None
    st.session_state[_K_ATTEMPTS]     = 0
    return False, 0


def _session_valid() -> bool:
    if not st.session_state.get(_K_AUTH):
        return False
    auth_time = st.session_state.get(_K_AUTH_TIME)
    if auth_time is None:
        return False
    elapsed_minutes = (time.monotonic() - auth_time) / 60
    if elapsed_minutes >= _SESSION_MINUTES:
        # Session expired — force re-login
        _logout(silent=True)
        return False
    return True


def _verify(username: str, password: str) -> bool:
    """Constant-time verification to prevent timing attacks."""
    # Compare username in constant time
    usernames_match = hmac.compare_digest(
        username.strip().encode(), _USERNAME.encode()
    )
    if not _PASSWORD_HASH:
        return False  # No hash configured — deny all
    try:
        password_ok = bcrypt.checkpw(password.encode(), _PASSWORD_HASH)
    except Exception:
        password_ok = False
    return usernames_match and password_ok


def _logout(silent: bool = False) -> None:
    st.session_state[_K_AUTH]         = False
    st.session_state[_K_AUTH_TIME]    = None
    st.session_state[_K_USERNAME]     = ""
    st.session_state[_K_ATTEMPTS]     = 0
    st.session_state[_K_LOCKED_UNTIL] = None
    st.session_state[_K_SAML_JWT]     = None
    st.session_state[_K_SAML_USER]    = ""
    st.session_state[_K_SAML_TENANT]  = "default"
    if not silent:
        st.rerun()


# ── SAML helpers ──────────────────────────────────────────────────────────────

def _exchange_saml_otp(token: str) -> dict[str, Any] | None:
    """
    Call GET /auth/saml/session?token=<otp> to exchange the one-time token
    for a JWT.  Returns the JSON payload or None on failure.
    Uses urllib (stdlib only — no httpx/requests dependency in dashboard).
    """
    import json
    import urllib.error
    import urllib.request

    url = f"{_SSO_SESSION_URL}?token={token}"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        # 401 = invalid/expired OTP — silently ignore (normal if user refreshes)
        if exc.code != 401:
            st.warning(f"SSO session error: HTTP {exc.code}")
        return None
    except Exception as exc:
        st.warning(f"Could not reach gateway for SSO handshake: {exc}")
        return None


def _verify_saml_jwt(jwt_token: str) -> dict[str, Any] | None:
    """
    Verify the stored JWT by calling GET /auth/saml/verify.
    Returns the decoded payload or None if invalid/expired.
    """
    import json
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        _SSO_VERIFY_URL,
        headers={"Authorization": f"Bearer {jwt_token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return json.loads(resp.read().decode())
    except (urllib.error.HTTPError, Exception):
        return None


def _saml_session_valid() -> bool:
    """
    Return True if a valid SAML JWT session exists.
    Verifies the JWT against the gateway (detects expiry, secret rotation).
    """
    jwt_token = st.session_state.get(_K_SAML_JWT)
    if not jwt_token:
        return False
    payload = _verify_saml_jwt(jwt_token)
    if payload is None:
        # JWT invalid or expired — clear it
        st.session_state[_K_SAML_JWT]  = None
        st.session_state[_K_SAML_USER] = ""
        return False
    # Refresh cached user info from latest payload
    st.session_state[_K_SAML_USER]   = payload.get("name") or payload.get("sub", "")
    st.session_state[_K_SAML_TENANT] = payload.get("tid", "default")
    return True


def _try_saml_otp_exchange() -> bool:
    """
    Check URL query params for a SAML OTP token.
    If found: exchange it for a JWT, store in session_state, clear the URL.
    Returns True if exchange succeeded (caller should st.rerun()).
    """
    token = st.query_params.get("token", "")
    if not token:
        return False

    # Clear the token from the URL immediately — prevents replay on refresh
    st.query_params.clear()

    data = _exchange_saml_otp(token)
    if data is None:
        st.error("SSO login failed or session expired. Please try again.")
        return False

    st.session_state[_K_SAML_JWT]    = data["access_token"]
    st.session_state[_K_SAML_USER]   = data.get("name") or data.get("email", "")
    st.session_state[_K_SAML_TENANT] = data.get("tenant_id", "default")
    return True


# ── CSS ───────────────────────────────────────────────────────────────────────

_LOGIN_CSS = """
<style>
  /* ── Hide Streamlit chrome on the login page ── */
  [data-testid="stSidebar"]       { display: none !important; }
  [data-testid="stHeader"]        { display: none !important; }
  [data-testid="stToolbar"]       { display: none !important; }
  footer                          { display: none !important; }
  .block-container                { padding-top: 6vh !important; }

  /* ── Login card ── */
  .warden-login-wrap {
    display: flex; justify-content: center; align-items: flex-start;
    min-height: 80vh; padding-top: 4vh;
  }
  .warden-login-card {
    background: #1a1f2e;
    border: 1px solid #2d3748;
    border-radius: 16px;
    padding: 52px 44px 44px;
    width: 100%;
    text-align: center;
    box-shadow: 0 8px 32px rgba(0,0,0,0.45);
  }
  .warden-logo        { font-size: 3.2rem; margin-bottom: 8px; }
  .warden-product     { font-size: 1.55rem; font-weight: 700; color: #e2e8f0; margin: 0 0 4px; }
  .warden-subtitle    { font-size: 0.82rem; color: #718096; letter-spacing: .06em;
                        text-transform: uppercase; margin-bottom: 36px; }
  .warden-divider     { border: none; border-top: 1px solid #2d3748; margin: 28px 0; }

  /* ── Alert boxes ── */
  .warden-alert {
    border-radius: 8px; padding: 12px 16px;
    font-size: 0.88rem; margin-bottom: 18px; text-align: left;
  }
  .warden-alert-error  { background:#2d1515; border:1px solid #c53030; color:#fc8181; }
  .warden-alert-lock   { background:#1a1200; border:1px solid #c05621; color:#f6ad55; }
  .warden-alert-dev    { background:#1a2400; border:1px solid #276749; color:#68d391; }
  .warden-alert-warn   { background:#1a1200; border:1px solid #b7791f; color:#ecc94b; }

  /* ── Session ribbon (top of dashboard when logged in) ── */
  .warden-session-badge {
    display: inline-flex; align-items: center; gap: 8px;
    background: #1a1f2e; border: 1px solid #2d3748;
    border-radius: 8px; padding: 6px 14px;
    font-size: 0.82rem; color: #718096;
  }
  .warden-session-dot  { width: 8px; height: 8px; border-radius: 50%;
                         background: #48bb78; display: inline-block; }
</style>
"""

# ── Login screen renderer ─────────────────────────────────────────────────────

def _render_login() -> None:
    st.markdown(_LOGIN_CSS, unsafe_allow_html=True)

    _, card_col, _ = st.columns([1, 1.6, 1])

    with card_col:
        st.markdown('<div class="warden-login-card">', unsafe_allow_html=True)
        st.markdown('<div class="warden-logo">🛡️</div>', unsafe_allow_html=True)
        st.markdown('<p class="warden-product">Shadow Warden AI</p>', unsafe_allow_html=True)
        st.markdown('<p class="warden-subtitle">Security Analytics Dashboard</p>', unsafe_allow_html=True)

        # ── Dev-mode notice ───────────────────────────────────────────────────
        if _DEV_MODE:
            st.markdown(
                '<div class="warden-alert warden-alert-dev">'
                '🟢 <strong>Dev mode</strong> — authentication bypassed.<br>'
                'Set <code>DASHBOARD_PASSWORD_HASH</code> to enable login.'
                '</div>',
                unsafe_allow_html=True,
            )
            st.markdown('</div>', unsafe_allow_html=True)
            # Auto-authenticate in dev mode
            st.session_state[_K_AUTH]      = True
            st.session_state[_K_AUTH_TIME] = time.monotonic()
            st.session_state[_K_USERNAME]  = _USERNAME
            st.rerun()
            return

        # ── Lockout check ─────────────────────────────────────────────────────
        locked, secs_remaining = _lockout_status()
        if locked:
            mins = (secs_remaining // 60) + 1
            st.markdown(
                f'<div class="warden-alert warden-alert-lock">'
                f'⛔ <strong>Account locked.</strong><br>'
                f'Too many failed attempts. Try again in '
                f'<strong>{mins} minute{"s" if mins != 1 else ""}</strong>.'
                f'</div>',
                unsafe_allow_html=True,
            )
            st.markdown('<hr class="warden-divider">', unsafe_allow_html=True)
            st.caption(f"Lockout resets automatically after {_LOCKOUT_MINUTES} minutes.")
            st.markdown('</div>', unsafe_allow_html=True)
            return

        # ── Login form ────────────────────────────────────────────────────────
        with st.form("warden_login", clear_on_submit=False):
            username = st.text_input(
                "Username",
                placeholder="admin",
                autocomplete="username",
            )
            password = st.text_input(
                "Password",
                type="password",
                placeholder="Enter your password",
                autocomplete="current-password",
            )
            submitted = st.form_submit_button(
                "Sign in  →",
                use_container_width=True,
                type="primary",
            )

        if submitted:
            if _verify(username, password):
                st.session_state[_K_AUTH]      = True
                st.session_state[_K_AUTH_TIME] = time.monotonic()
                st.session_state[_K_USERNAME]  = username.strip()
                st.session_state[_K_ATTEMPTS]  = 0
                st.rerun()
            else:
                st.session_state[_K_ATTEMPTS] += 1
                attempts_so_far = st.session_state[_K_ATTEMPTS]

                if attempts_so_far >= _MAX_ATTEMPTS:
                    st.session_state[_K_LOCKED_UNTIL] = (
                        time.monotonic() + _LOCKOUT_MINUTES * 60
                    )
                    st.rerun()
                else:
                    remaining = _MAX_ATTEMPTS - attempts_so_far
                    st.markdown(
                        f'<div class="warden-alert warden-alert-error">'
                        f'❌ <strong>Invalid credentials.</strong><br>'
                        f'{remaining} attempt{"s" if remaining != 1 else ""} '
                        f'remaining before lockout.'
                        f'</div>',
                        unsafe_allow_html=True,
                    )

        # ── SSO button (shown alongside or instead of password form) ─────
        if _SAML_ENABLED:
            st.markdown('<hr class="warden-divider">', unsafe_allow_html=True)
            st.markdown(
                f'<a href="{_SSO_LOGIN_URL}" target="_self" style="text-decoration:none;">'
                '<div style="background:#2b6cb0;color:#fff;border-radius:8px;'
                'padding:10px 20px;text-align:center;font-weight:600;font-size:.95rem;'
                'letter-spacing:.03em;cursor:pointer;">'
                '🏢&nbsp; Login with Microsoft / Okta'
                '</div></a>',
                unsafe_allow_html=True,
            )

        st.markdown('<hr class="warden-divider">', unsafe_allow_html=True)
        st.caption("Shadow Warden AI • Authorised access only")
        st.markdown('</div>', unsafe_allow_html=True)


# ── Sidebar logout widget (call from dashboard after require_auth passes) ──────

def _render_sidebar_session() -> None:
    """Inject session info + logout button into the sidebar."""
    # SAML session takes priority over password session for display
    if st.session_state.get(_K_SAML_JWT):
        user   = st.session_state.get(_K_SAML_USER, "SSO User")
        tenant = st.session_state.get(_K_SAML_TENANT, "default")
        st.sidebar.markdown(
            f'<div class="warden-session-badge">'
            f'<span class="warden-session-dot"></span>'
            f'<span>🏢 {user}<br><small style="color:#4a5568">tenant: {tenant}</small></span>'
            f'</div>',
            unsafe_allow_html=True,
        )
    else:
        user = st.session_state.get(_K_USERNAME, _USERNAME)
        auth_time = st.session_state.get(_K_AUTH_TIME)
        if auth_time is not None:
            elapsed   = int((time.monotonic() - auth_time) / 60)
            remaining = max(0, _SESSION_MINUTES - elapsed)
            st.sidebar.markdown(
                f'<div class="warden-session-badge">'
                f'<span class="warden-session-dot"></span>'
                f'<span>{user} &nbsp;·&nbsp; {remaining} min left</span>'
                f'</div>',
                unsafe_allow_html=True,
            )
    if st.sidebar.button("Sign out", use_container_width=True):
        _logout()


# ── Public API ────────────────────────────────────────────────────────────────

def require_auth() -> None:
    """
    Enforce authentication.  Call immediately after st.set_page_config().

    Priority order:
      1. SAML OTP in ``?token=`` query param — exchange for JWT, rerun.
      2. Valid SAML JWT in session_state     — skip to dashboard.
      3. Valid password session              — skip to dashboard.
      4. Dev mode (neither method configured) — auto-login with green banner.
      5. Not authenticated                   — show login screen + SSO button.
    """
    _init_state()

    # ── Step 1: SAML OTP exchange ─────────────────────────────────────────────
    # The ACS endpoint redirects here with ?token=<otp> after IdP login.
    # Exchange it for a JWT and rerun so the URL is clean.
    if _SAML_ENABLED and st.query_params.get("token"):
        if _try_saml_otp_exchange():
            st.rerun()
        # Exchange failed — fall through to login screen
        _render_login()
        st.stop()

    # ── Step 2: Valid SAML JWT session ────────────────────────────────────────
    if _SAML_ENABLED and st.session_state.get(_K_SAML_JWT) and _saml_session_valid():
        _render_sidebar_session()
        return
    # JWT expired — fall through to login screen

    # ── Step 3: Valid password session ────────────────────────────────────────
    if _session_valid():
        _render_sidebar_session()
        return

    # ── Step 4 + 5: Show login screen (handles dev mode internally) ───────────
    _render_login()
    st.stop()


def get_saml_tenant() -> str:
    """
    Return the tenant_id of the currently authenticated SAML user.
    Returns "default" if not using SAML auth or no tenant was mapped.
    Useful for dashboard code that filters data by tenant.
    """
    return st.session_state.get(_K_SAML_TENANT, "default")


# ── CLI — hash generator ──────────────────────────────────────────────────────

if __name__ == "__main__":
    import getpass
    import sys

    print("Shadow Warden AI — Dashboard Password Hash Generator")
    print("─" * 52)

    if len(sys.argv) > 1:
        raw = sys.argv[1]
    else:
        raw = getpass.getpass("Enter password to hash: ")
        confirm = getpass.getpass("Confirm password:        ")
        if raw != confirm:
            print("ERROR: Passwords do not match.")
            sys.exit(1)

    hashed = bcrypt.hashpw(raw.encode(), bcrypt.gensalt(rounds=12))
    print("\nAdd this to your .env file:\n")
    print(f"DASHBOARD_PASSWORD_HASH={hashed.decode()}")
    print("\nDo NOT share or commit this hash to version control.")
