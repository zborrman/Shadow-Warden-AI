/**
 * background.js — Shadow Warden AI Service Worker
 *
 * Responsibilities:
 *  - Store and serve config (gateway URL, tenant API key) via chrome.storage
 *  - Receive block events from content.js via chrome.runtime.onMessage
 *  - Show desktop notifications on block events
 *  - Track session statistics (blocks today, cost saved)
 */

// ── Default config ────────────────────────────────────────────────────────────

const DEFAULT_CONFIG = {
  gatewayUrl:   "http://localhost:8001",   // Shadow Warden on Hetzner or local
  apiKey:       "",                         // X-API-Key from onboarding
  tenantId:     "default",
  enabled:      true,
  notifyOnBlock: true,
  minRiskNotify: "high",                   // low | medium | high | block
};

// ── Config resolution: managed (GPO) > sync (user) > defaults ────────────────
//
// chrome.storage.managed is populated by Windows Registry GPO keys written by
// Invoke-WardenProvision.ps1.  When present, it takes precedence and the UI is
// locked so end-users cannot override IT policy.

async function _resolveConfig() {
  let managed = {};
  try {
    managed = await chrome.storage.managed.get(null);
  } catch (_) {
    // chrome.storage.managed is unavailable in non-enterprise builds — ignore
  }

  const synced = await chrome.storage.sync.get(null);

  // Merge: managed keys win over user-synced keys, both win over defaults
  return { ...DEFAULT_CONFIG, ...synced, ...managed };
}

// ── Initialise storage on install ────────────────────────────────────────────

chrome.runtime.onInstalled.addListener(async () => {
  let managed = {};
  try { managed = await chrome.storage.managed.get(null); } catch (_) {}

  const isManagedDeploy = !!(managed.gatewayUrl || managed.apiKey);

  if (isManagedDeploy) {
    // GPO-provisioned: sync any managed keys into storage.sync so content.js
    // can read them via the standard GET_CONFIG message without needing managed
    // storage access itself.
    await chrome.storage.sync.set({ ...DEFAULT_CONFIG, ...managed });
    console.log("[Shadow Warden] GPO-managed config applied for tenant:", managed.tenantId);
  } else {
    const existing = await chrome.storage.sync.get(null);
    if (!existing.gatewayUrl) {
      await chrome.storage.sync.set(DEFAULT_CONFIG);
    }
  }

  await _resetDailyStats();
  console.log("[Shadow Warden] Extension installed.");
  // Run extension risk scan on install
  _scanInstalledExtensions();
});

// Q2.4 — Extension Risk Scanner
// On install and every 6h, scan installed extensions against Warden's risk DB.
// Requires the 'management' permission in manifest.json.
async function _scanInstalledExtensions() {
  const cfg = await _resolveConfig();
  if (!cfg.enabled || !cfg.gatewayUrl) return;

  let extensions = [];
  try {
    extensions = await chrome.management.getAll();
  } catch (_) {
    return;  // management API not available (Firefox or unprivileged)
  }

  const payload = {
    tenant_id: cfg.tenantId || "default",
    extensions: extensions
      .filter(e => e.type === "extension" && e.enabled && e.id !== chrome.runtime.id)
      .map(e => ({
        id:               e.id,
        name:             e.name,
        version:          e.version,
        permissions:      e.permissions || [],
        host_permissions: e.hostPermissions || [],
        enabled:          e.enabled,
      })),
  };

  try {
    const resp = await fetch(`${cfg.gatewayUrl}/scan/extensions`, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "X-API-Key": cfg.apiKey || "" },
      body:    JSON.stringify(payload),
    });
    if (!resp.ok) return;

    const result = await resp.json();
    if (result.flagged_count > 0) {
      const names = result.flagged.filter(f => f.risk_level !== "LOW").map(f => f.name).slice(0, 3);
      if (names.length > 0) {
        chrome.notifications.create({
          type:     "basic",
          iconUrl:  "icons/icon48.png",
          title:    "Shadow Warden — Extension Risk Detected",
          message:  `⚠️ Risky extensions found: ${names.join(", ")}. Check extension settings.`,
          priority: 2,
        });
      }
    }
    await chrome.storage.local.set({ lastExtensionScan: Date.now(), extensionScanResult: result });
  } catch (_) {}
}

// Re-scan every 6 hours
setInterval(_scanInstalledExtensions, 6 * 3_600_000);

// ── Warden Identity — OIDC token management ───────────────────────────────────
//
// The Service Worker is the only place where the OIDC token is held.
// content.js (world: MAIN) never touches the token — it sends WARDEN_FILTER
// messages and gets back a filter result.  This prevents ChatGPT/Claude JS
// from ever seeing the Authorization header or the token value.
//
// Token storage: chrome.storage.local  ("oidcToken", "oidcEmail", "oidcExpiry")
// Token refresh: handled transparently by chrome.identity before each request.

/**
 * Get a valid OIDC id_token from the Chrome identity service.
 * Uses launchWebAuthFlow with response_type=id_token for a proper JWT.
 * Returns null if the user is not signed in or declined consent.
 */
async function _getOidcToken(interactive = false) {
  // Try cached token first (check expiry with 60 s buffer)
  const stored = await chrome.storage.local.get(["oidcToken", "oidcExpiry"]);
  if (stored.oidcToken && stored.oidcExpiry && Date.now() < (stored.oidcExpiry - 60_000)) {
    return stored.oidcToken;
  }

  // Get fresh token via chrome.identity
  try {
    const cfg = await _resolveConfig();

    // Build OIDC auth URL for Google
    const nonce = crypto.randomUUID();
    const redirectUrl = chrome.identity.getRedirectURL();
    const authUrl = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    authUrl.searchParams.set("client_id", cfg.oidcClientId || "");
    authUrl.searchParams.set("redirect_uri", redirectUrl);
    authUrl.searchParams.set("response_type", "id_token");
    authUrl.searchParams.set("scope", "openid email profile");
    authUrl.searchParams.set("nonce", nonce);
    authUrl.searchParams.set("prompt", interactive ? "select_account" : "none");

    const resultUrl = await chrome.identity.launchWebAuthFlow({
      url: authUrl.toString(),
      interactive,
    });

    if (!resultUrl) return null;

    // Extract id_token from URL fragment
    const fragment = new URL(resultUrl).hash.substring(1);
    const params = new URLSearchParams(fragment);
    const idToken = params.get("id_token");
    if (!idToken) return null;

    // Parse expiry from JWT payload (no signature needed — just for caching)
    const payloadB64 = idToken.split(".")[1];
    const payload    = JSON.parse(atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/")));
    const expiry     = (payload.exp || 0) * 1000;  // ms
    const email      = payload.email || "";

    await chrome.storage.local.set({ oidcToken: idToken, oidcExpiry: expiry, oidcEmail: email });
    console.log("[Shadow Warden] OIDC signed in:", email);
    return idToken;

  } catch (err) {
    // User not signed in or cancelled — not an error
    if (!String(err).includes("canceled") && !String(err).includes("not signed in")) {
      console.warn("[Shadow Warden] OIDC token fetch failed:", err.message);
    }
    return null;
  }
}

/**
 * Sign out: clear stored OIDC token + revoke with Google.
 */
async function _oidcSignOut() {
  const stored = await chrome.storage.local.get("oidcToken");
  if (stored.oidcToken) {
    // Revoke token via Google endpoint (best-effort, non-fatal)
    fetch(`https://oauth2.googleapis.com/revoke?token=${stored.oidcToken}`, { method: "POST" })
      .catch(() => {});
  }
  await chrome.storage.local.remove(["oidcToken", "oidcExpiry", "oidcEmail"]);
  console.log("[Shadow Warden] OIDC signed out.");
}

/**
 * Build authenticated headers for Shadow Warden API calls.
 * OIDC Bearer > X-API-Key > dev mode (no header).
 */
async function _authHeaders(cfg) {
  const headers = { "Content-Type": "application/json" };
  const oidcToken = await _getOidcToken(false);
  if (oidcToken) {
    headers["Authorization"] = `Bearer ${oidcToken}`;
  } else if (cfg.apiKey) {
    headers["X-API-Key"] = cfg.apiKey;
  }
  return headers;
}

/**
 * Call POST /ext/filter from the isolated Service Worker context.
 * Authenticates with OIDC Bearer token if available; falls back to X-API-Key.
 * The Authorization header is never exposed to the page's JS context.
 */
async function _wardenFilter({ content, tenantId, context }) {
  const cfg = await _resolveConfig();

  if (!cfg.enabled) {
    return { allowed: true, risk_level: "low", flags: [], reason: "Warden disabled", pii_action: "pass" };
  }

  const headers = await _authHeaders(cfg);

  try {
    const resp = await fetch(`${cfg.gatewayUrl}/ext/filter`, {
      method:  "POST",
      headers,
      body: JSON.stringify({
        content,
        tenant_id: tenantId || cfg.tenantId,
        context,
      }),
    });

    if (resp.status === 401) {
      console.warn("[Shadow Warden] Gateway auth error: 401");
      return { allowed: true, risk_level: "low", flags: [], reason: "Auth error — fail open", pii_action: "pass" };
    }

    if (resp.status === 402) {
      // Subscription lapsed — block the prompt and prompt the user to renew
      const body = await resp.json().catch(() => ({}));
      const msg  = (body?.detail) || "Your organisation's Shadow Warden subscription has lapsed.";
      console.warn("[Shadow Warden] Subscription lapsed (402):", msg);
      return {
        allowed:    false,
        data_class: "subscription",
        reason:     msg,
        suggestion: "Contact your IT administrator to renew the Shadow Warden subscription.",
        risk_level: "block",
        flags:      ["subscription_lapsed"],
        pii_action: "block",
      };
    }

    if (resp.status === 403) {
      const body = await resp.json().catch(() => ({}));
      const detail = body?.detail || body;
      return {
        allowed:    false,
        data_class: detail?.data_class || "red",
        reason:     detail?.reason     || "Content blocked by policy.",
        suggestion: detail?.suggestion || "",
        risk_level: "block",
        flags:      [],
        pii_action: "block",
      };
    }

    if (!resp.ok) {
      console.warn("[Shadow Warden] Gateway error:", resp.status);
      return { allowed: true, risk_level: "low", flags: [], reason: "Gateway error — fail open", pii_action: "pass" };
    }

    return await resp.json();

  } catch (err) {
    console.warn("[Shadow Warden] Gateway unreachable:", err.message);
    return { allowed: true, risk_level: "low", flags: [], reason: "Unreachable — fail open", pii_action: "pass" };
  }
}

// ── Reversible PII Vault — unmask LLM response ─────────────────────────────
//
// After the LLM generates a response (SSE stream complete), content.js sends
// WARDEN_UNMASK with the buffered response text + pii_session_id.
// We call /ext/unmask in the Service Worker (auth header included) and return
// the restored text with [PERSON_1] → "John Doe" etc.

async function _wardenUnmask({ text, sessionId }) {
  const cfg = await _resolveConfig();
  const headers = await _authHeaders(cfg);

  try {
    const resp = await fetch(`${cfg.gatewayUrl}/ext/unmask`, {
      method:  "POST",
      headers,
      body: JSON.stringify({ text, session_id: sessionId }),
    });

    if (!resp.ok) {
      console.warn("[Shadow Warden] /ext/unmask returned", resp.status, "— returning original");
      return { unmasked: text, session_id: sessionId };
    }

    return await resp.json();   // { unmasked: "...", session_id: "..." }

  } catch (err) {
    console.warn("[Shadow Warden] /ext/unmask unreachable:", err.message);
    return { unmasked: text, session_id: sessionId };   // fail-open
  }
}

// ── Message handler (from content.js) ────────────────────────────────────────

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "WARDEN_BLOCK") {
    _handleBlockEvent(message.data);
    sendResponse({ ok: true });
  }

  if (message.type === "GET_CONFIG") {
    _resolveConfig().then(sendResponse);
    return true;   // keep channel open for async response
  }

  if (message.type === "GET_STATS") {
    chrome.storage.local.get(["blocksToday", "requestsToday"]).then(sendResponse);
    return true;
  }

  if (message.type === "IS_MANAGED") {
    _resolveConfig().then(cfg => sendResponse({ managed: !!cfg.managed }));
    return true;
  }

  // ── Warden Identity: sign in (interactive — user must approve) ────────────
  if (message.type === "WARDEN_SIGNIN") {
    _getOidcToken(true).then(async (token) => {
      if (token) {
        const stored = await chrome.storage.local.get("oidcEmail");
        sendResponse({ ok: true, email: stored.oidcEmail || "" });
      } else {
        sendResponse({ ok: false, error: "Sign-in cancelled or failed." });
      }
    });
    return true;
  }

  // ── Warden Identity: sign out ─────────────────────────────────────────────
  if (message.type === "WARDEN_SIGNOUT") {
    _oidcSignOut().then(() => sendResponse({ ok: true }));
    return true;
  }

  // ── Warden Identity: get current auth state ───────────────────────────────
  if (message.type === "GET_AUTH_STATE") {
    chrome.storage.local.get(["oidcEmail", "oidcToken", "oidcExpiry"]).then((s) => {
      const signedIn = !!(s.oidcToken && s.oidcExpiry && Date.now() < s.oidcExpiry);
      sendResponse({ signedIn, email: s.oidcEmail || "" });
    });
    return true;
  }

  // ── Relay filter call from content.js through the isolated Service Worker ──
  //
  // This is the MV3 security pattern: content.js (world:MAIN) never touches
  // the auth token or makes authenticated HTTP calls. All gateway requests
  // originate here in the Service Worker's isolated context.
  if (message.type === "WARDEN_FILTER") {
    _wardenFilter(message.payload).then(sendResponse);
    return true;
  }

  // ── Reversible PII: unmask LLM response after stream completes ──────────
  //
  // content.js buffers the full SSE stream response, then sends WARDEN_UNMASK.
  // We call /ext/unmask here (auth included) and return the de-tokenised text.
  if (message.type === "WARDEN_UNMASK") {
    _wardenUnmask(message.payload).then(sendResponse);
    return true;
  }

  // ── Dollar Impact: fetch /tenant/impact for the Impact popup tab ─────────
  //
  // Popup sends GET_TENANT_IMPACT; we call the gateway with auth headers here
  // in the Service Worker (token never exposed to the popup's page context).
  if (message.type === "GET_TENANT_IMPACT") {
    _wardenTenantImpact(message.period || 30).then(sendResponse);
    return true;
  }
});

// ── Dollar Impact Calculator — fetch /tenant/impact ──────────────────────────

/**
 * Call GET /tenant/impact on the gateway with the current auth headers.
 * Returns the parsed JSON payload, or { error: "..." } on failure.
 * Cached for 5 minutes in chrome.storage.local to keep popup snappy.
 */
async function _wardenTenantImpact(period = 30) {
  const cfg         = await _resolveConfig();
  const cacheKey    = "impactCache";
  const cacheAgeKey = "impactCacheTs";
  const CACHE_TTL   = 5 * 60 * 1000; // 5 minutes

  // Return cached data if still fresh
  const cached = await chrome.storage.local.get([cacheKey, cacheAgeKey]);
  if (cached[cacheKey] && cached[cacheAgeKey] && (Date.now() - cached[cacheAgeKey]) < CACHE_TTL) {
    return cached[cacheKey];
  }

  const url = `${cfg.gatewayUrl}/tenant/impact?period=${period}`;
  try {
    const headers = await _authHeaders(cfg);
    const resp    = await fetch(url, { method: "GET", headers });

    if (resp.status === 402) {
      return { error: "Subscription lapsed — contact your IT administrator." };
    }
    if (resp.status === 401 || resp.status === 403) {
      return { error: "Not authorised — sign in with Google Workspace first." };
    }
    if (!resp.ok) {
      return { error: `Gateway returned ${resp.status}` };
    }

    const data = await resp.json();
    await chrome.storage.local.set({ [cacheKey]: data, [cacheAgeKey]: Date.now() });
    return data;

  } catch (err) {
    console.warn("[Shadow Warden] Impact fetch failed:", err.message);
    // Return stale cache if available rather than a hard error
    if (cached[cacheKey]) return cached[cacheKey];
    return { error: `Cannot reach ${cfg.gatewayUrl} — check your connection.` };
  }
}

// ── Block event handler ───────────────────────────────────────────────────────

async function _handleBlockEvent(data) {
  const { tenantId, riskLevel, dataClass, reason, site } = data;

  // Increment daily block counter
  const stats = await chrome.storage.local.get(["blocksToday", "requestsToday"]);
  await chrome.storage.local.set({
    blocksToday:    (stats.blocksToday    || 0) + 1,
    requestsToday:  (stats.requestsToday  || 0) + 1,
    lastBlockTs:    new Date().toISOString(),
    lastBlockSite:  site,
  });

  // Desktop notification
  const cfg = await chrome.storage.sync.get(["notifyOnBlock", "minRiskNotify"]);
  if (cfg.notifyOnBlock && _riskAboveThreshold(riskLevel, cfg.minRiskNotify)) {
    chrome.notifications.create({
      type:     "basic",
      iconUrl:  "icons/icon48.png",
      title:    "Shadow Warden AI — Blocked",
      message:  `${_riskEmoji(riskLevel)} ${reason || "Confidential data detected."}`,
      priority: 2,
    });
  }

  console.log(`[Shadow Warden] Block event: site=${site} risk=${riskLevel} class=${dataClass}`);
}

// ── Daily stats reset (midnight) ──────────────────────────────────────────────

async function _resetDailyStats() {
  await chrome.storage.local.set({ blocksToday: 0, requestsToday: 0 });
}

// Re-check every hour — reset if date changed
setInterval(async () => {
  const last = await chrome.storage.local.get("lastResetDate");
  const today = new Date().toDateString();
  if (last.lastResetDate !== today) {
    await _resetDailyStats();
    await chrome.storage.local.set({ lastResetDate: today });
  }
}, 3_600_000);

// ── Helpers ───────────────────────────────────────────────────────────────────

const _RISK_ORDER = { low: 0, medium: 1, high: 2, block: 3 };

function _riskAboveThreshold(risk, threshold) {
  return (_RISK_ORDER[risk] || 0) >= (_RISK_ORDER[threshold] || 2);
}

function _riskEmoji(risk) {
  return { low: "🟡", medium: "🟠", high: "🔴", block: "🚫" }[risk] || "⚠️";
}
