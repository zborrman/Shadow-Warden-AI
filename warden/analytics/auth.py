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
from typing import Tuple

import bcrypt
import streamlit as st

# ── Configuration ─────────────────────────────────────────────────────────────

_USERNAME         = os.getenv("DASHBOARD_USERNAME", "admin")
_PASSWORD_HASH    = os.getenv("DASHBOARD_PASSWORD_HASH", "").encode()
_SESSION_MINUTES  = int(os.getenv("DASHBOARD_SESSION_MINUTES", "60"))
_MAX_ATTEMPTS     = int(os.getenv("DASHBOARD_MAX_ATTEMPTS", "5"))
_LOCKOUT_MINUTES  = int(os.getenv("DASHBOARD_LOCKOUT_MINUTES", "15"))

_DEV_MODE = not bool(_PASSWORD_HASH)

# ── Session-state keys (prefixed to avoid collisions with dashboard keys) ─────

_K_AUTH         = "_wa_authenticated"
_K_AUTH_TIME    = "_wa_auth_time"
_K_ATTEMPTS     = "_wa_failed_attempts"
_K_LOCKED_UNTIL = "_wa_locked_until"
_K_USERNAME     = "_wa_username"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _init_state() -> None:
    defaults: dict = {
        _K_AUTH:         False,
        _K_AUTH_TIME:    None,
        _K_ATTEMPTS:     0,
        _K_LOCKED_UNTIL: None,
        _K_USERNAME:     "",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _lockout_status() -> Tuple[bool, int]:
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
    if not silent:
        st.rerun()


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

        st.markdown('<hr class="warden-divider">', unsafe_allow_html=True)
        st.caption("Shadow Warden AI • Authorised access only")
        st.markdown('</div>', unsafe_allow_html=True)


# ── Sidebar logout widget (call from dashboard after require_auth passes) ──────

def _render_sidebar_session() -> None:
    """Inject session info + logout button into the sidebar."""
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

    Behaviour:
      • If DASHBOARD_PASSWORD_HASH is unset:  dev mode (auto-login, green banner).
      • If session is valid:                  returns immediately.
      • If session expired:                   clears state, shows login, st.stop().
      • If not authenticated:                 shows login screen, st.stop().
    """
    _init_state()

    if _session_valid():
        _render_sidebar_session()
        return

    _render_login()
    st.stop()


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
    print(f"\nAdd this to your .env file:\n")
    print(f"DASHBOARD_PASSWORD_HASH={hashed.decode()}")
    print(f"\nDo NOT share or commit this hash to version control.")
