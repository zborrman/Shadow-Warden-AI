/**
 * Shadow Warden AI — Automatic Session Manager
 *
 * Features:
 *   - Access token stored in localStorage ('warden_token')
 *   - Proactive refresh at 80% of token lifetime (before expiry)
 *   - On any 401: auto-refresh once, retry original request
 *   - Token rotation: every refresh issues a new refresh token (HttpOnly cookie)
 *   - Cross-tab sync: logout/refresh in one tab propagates to all open tabs
 *   - Expiry warning: fires registered callbacks 5 min before token expires
 *   - Session.authFetch(): drop-in fetch() replacement that handles Bearer auth
 */
const Session = (() => {
  const _KEY         = 'warden_token';
  const _REFRESH_URL = '/portal/auth/refresh';
  const _LOGOUT_URL  = '/portal/auth/logout';
  const _LOGIN_URL   = '/login';
  const _WARN_BEFORE = 5 * 60;       // seconds before expiry to fire warning
  const _REFRESH_AT  = 0.80;         // refresh at 80% of token lifetime elapsed

  let _refreshTimer   = null;        // setTimeout handle for proactive refresh
  let _warnTimer      = null;        // setTimeout handle for expiry warning
  let _refreshing     = null;        // in-flight refresh Promise (deduplicates concurrent calls)
  let _warnCallbacks  = [];          // registered via Session.onExpiry()

  // ── JWT helpers ────────────────────────────────────────────────────────────

  function _decode(token) {
    try {
      const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      return JSON.parse(atob(b64));
    } catch {
      return null;
    }
  }

  function _exp(token) {
    const p = _decode(token);
    return p ? p.exp : null;        // seconds since epoch, or null
  }

  function _iat(token) {
    const p = _decode(token);
    return p ? p.iat : null;
  }

  // ── Timer management ───────────────────────────────────────────────────────

  function _clearTimers() {
    clearTimeout(_refreshTimer);
    clearTimeout(_warnTimer);
    _refreshTimer = null;
    _warnTimer    = null;
  }

  function _scheduleRefresh(token) {
    clearTimeout(_refreshTimer);
    const exp = _exp(token);
    const iat = _iat(token);
    if (!exp) return;

    const now      = Math.floor(Date.now() / 1000);
    const lifetime = exp - (iat || now);          // total TTL in seconds
    const elapsed  = now - (iat || now);
    const refreshIn = Math.max(lifetime * _REFRESH_AT - elapsed, 30); // at least 30s away
    const secsLeft  = exp - now;

    if (secsLeft <= 5) {
      // Token essentially expired — refresh immediately
      _refresh();
      return;
    }

    _refreshTimer = setTimeout(_refresh, Math.min(refreshIn, secsLeft - 30) * 1000);
  }

  function _scheduleWarn(token) {
    clearTimeout(_warnTimer);
    if (!_warnCallbacks.length) return;
    const exp = _exp(token);
    if (!exp) return;
    const now    = Math.floor(Date.now() / 1000);
    const warnIn = (exp - _WARN_BEFORE - now) * 1000;
    if (warnIn > 0) {
      _warnTimer = setTimeout(() => {
        const remaining = _exp(getToken()) - Math.floor(Date.now() / 1000);
        _warnCallbacks.forEach(cb => cb(remaining));
      }, warnIn);
    }
  }

  // ── Core token operations ──────────────────────────────────────────────────

  function getToken() {
    return localStorage.getItem(_KEY);
  }

  function setToken(token) {
    localStorage.setItem(_KEY, token);
    _scheduleRefresh(token);
    _scheduleWarn(token);
  }

  function _clearToken() {
    localStorage.removeItem(_KEY);
    _clearTimers();
  }

  // ── Refresh ────────────────────────────────────────────────────────────────

  async function _refresh() {
    // Deduplicate: if a refresh is already in flight, wait for it
    if (_refreshing) return _refreshing;

    _refreshing = (async () => {
      try {
        const resp = await fetch(_REFRESH_URL, {
          method: 'POST',
          credentials: 'include',    // send HttpOnly refresh cookie
        });
        if (!resp.ok) throw new Error('refresh_failed');
        const data = await resp.json();
        setToken(data.access_token);
        return data.access_token;
      } catch {
        // Refresh failed — session is dead, go to login
        await logout(false);
        return null;
      } finally {
        _refreshing = null;
      }
    })();

    return _refreshing;
  }

  // ── Public API ─────────────────────────────────────────────────────────────

  /**
   * Redirect to /login if no token, or if token is expired and refresh fails.
   * Call at the top of every protected page.
   */
  async function requireAuth() {
    const token = getToken();
    if (!token) {
      window.location.href = _LOGIN_URL;
      return false;
    }
    const exp = _exp(token);
    const now = Math.floor(Date.now() / 1000);
    if (exp && exp < now) {
      // Expired — try refresh before giving up
      const newToken = await _refresh();
      if (!newToken) return false; // logout() already redirected
    } else {
      _scheduleRefresh(token);
      _scheduleWarn(token);
    }
    return true;
  }

  /**
   * Drop-in replacement for fetch() on authenticated endpoints.
   * Automatically:
   *   1. Adds Authorization: Bearer <token> header
   *   2. On 401: refreshes once, then retries the original request
   *   3. On double-401 (refresh also fails): calls logout()
   */
  async function authFetch(url, options = {}) {
    let token = getToken();

    const _buildHeaders = (tok) => ({
      ...(options.headers || {}),
      ...(tok ? { Authorization: 'Bearer ' + tok } : {}),
    });

    let resp = await fetch(url, {
      ...options,
      headers: _buildHeaders(token),
      credentials: 'include',
    });

    if (resp.status === 401) {
      const newToken = await _refresh();
      if (!newToken) return resp; // logout() already redirected

      resp = await fetch(url, {
        ...options,
        headers: _buildHeaders(newToken),
        credentials: 'include',
      });
    }

    return resp;
  }

  /**
   * Logout: clear token, call server to invalidate refresh cookie, redirect.
   * @param {boolean} redirect - set false to skip redirect (used internally)
   */
  async function logout(redirect = true) {
    _clearToken();
    try {
      await fetch(_LOGOUT_URL, { method: 'POST', credentials: 'include' });
    } catch { /* ignore network errors */ }
    if (redirect) window.location.href = _LOGIN_URL;
  }

  /**
   * Register a callback fired ~5 min before the access token expires.
   * Useful for showing an "expiring soon" warning banner.
   * @param {function(remainingSeconds: number): void} callback
   */
  function onExpiry(callback) {
    _warnCallbacks.push(callback);
    const token = getToken();
    if (token) _scheduleWarn(token);
  }

  // ── Cross-tab sync ─────────────────────────────────────────────────────────
  window.addEventListener('storage', (e) => {
    if (e.key !== _KEY) return;
    if (!e.newValue) {
      // Another tab logged out — follow
      _clearTimers();
      window.location.href = _LOGIN_URL;
    } else if (e.newValue !== e.oldValue) {
      // Another tab refreshed the token — adopt new token timers
      _clearTimers();
      _scheduleRefresh(e.newValue);
      _scheduleWarn(e.newValue);
    }
  });

  return { getToken, setToken, requireAuth, authFetch, logout, onExpiry };
})();
