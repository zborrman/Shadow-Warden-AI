/**
 * popup.js — Shadow Warden AI Extension Popup
 *
 * Handles:
 *  - Loading and saving config to chrome.storage.sync
 *  - Displaying today's block/request stats from chrome.storage.local
 *  - Enable/disable toggle
 *  - Connection test (POST /health to Shadow Warden)
 */

// ── Load state on popup open ──────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  await _loadConfig();
  await _loadStats();
  await _loadAuthState();
});

// ── Config (managed > sync > defaults) ───────────────────────────────────────

async function _loadConfig() {
  // Ask background to resolve config (managed keys win over sync keys)
  const cfg = await new Promise(resolve =>
    chrome.runtime.sendMessage({ type: "GET_CONFIG" }, resolve)
  );

  document.getElementById("gateway-url").value = cfg.gatewayUrl || "";
  document.getElementById("api-key").value     = cfg.apiKey     || "";
  document.getElementById("tenant-id").value   = cfg.tenantId   || "default";
  document.getElementById("ollama-url").value  = cfg.ollamaUrl  || "http://localhost:3000";

  _updateStatusUI(cfg.enabled !== false, !!cfg.apiKey);

  const tenantDisplay = document.getElementById("tenant-display");
  tenantDisplay.textContent = cfg.tenantId && cfg.apiKey
    ? cfg.tenantId
    : "Not configured";

  // Lock the UI if this is a GPO-managed deployment
  if (cfg.managed) {
    _applyManagedLock();
  }
}

// ── Warden Identity — OIDC auth state ────────────────────────────────────────

async function _loadAuthState() {
  const state = await new Promise(resolve =>
    chrome.runtime.sendMessage({ type: "GET_AUTH_STATE" }, resolve)
  );

  if (state?.signedIn) {
    _showOidcSignedIn(state.email);
  } else {
    _showOidcSignedOut();
  }
}

function _showOidcSignedIn(email) {
  document.getElementById("oidc-signout-view").style.display = "none";
  document.getElementById("oidc-signin-view").style.display  = "block";
  document.getElementById("oidc-email-display").textContent  = email || "Signed in";

  // When signed in via OIDC, collapse the manual API key section (still accessible)
  const configSection = document.getElementById("config-section");
  if (configSection) configSection.style.opacity = "0.5";

  // Update status bar — OIDC auth counts as "configured"
  const dot  = document.getElementById("status-dot");
  const text = document.getElementById("status-text");
  if (dot)  dot.className   = "dot active";
  if (text) text.textContent = "Protected · Warden Identity";

  const tenantDisplay = document.getElementById("tenant-display");
  if (tenantDisplay) tenantDisplay.textContent = email || "OIDC";
}

function _showOidcSignedOut() {
  document.getElementById("oidc-signout-view").style.display = "block";
  document.getElementById("oidc-signin-view").style.display  = "none";

  const configSection = document.getElementById("config-section");
  if (configSection) configSection.style.opacity = "1";
}

async function _handleGoogleSignIn() {
  const btn = document.getElementById("signin-google-btn");
  btn.disabled    = true;
  btn.textContent = "Signing in…";

  const result = await new Promise(resolve =>
    chrome.runtime.sendMessage({ type: "WARDEN_SIGNIN" }, resolve)
  );

  btn.disabled    = false;
  btn.innerHTML   = `<svg width="15" height="15" viewBox="0 0 48 48" style="vertical-align:middle;margin-right:7px;flex-shrink:0"><path fill="#EA4335" d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"/><path fill="#4285F4" d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"/><path fill="#FBBC05" d="M10.53 28.59c-.48-1.45-.76-2.99-.76-4.59s.27-3.14.76-4.59l-7.98-6.19C.92 16.46 0 20.12 0 24c0 3.88.92 7.54 2.56 10.78l7.97-6.19z"/><path fill="#34A853" d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"/></svg>Sign in with Google Workspace`;

  if (result?.ok) {
    _showOidcSignedIn(result.email);
    _showToast(`✅ Signed in as ${result.email}`, "success");
  } else {
    _showToast(result?.error || "Sign-in failed — try again.", "error");
  }
}

async function _handleSignOut() {
  const btn = document.getElementById("signout-btn");
  btn.disabled    = true;
  btn.textContent = "Signing out…";

  await new Promise(resolve =>
    chrome.runtime.sendMessage({ type: "WARDEN_SIGNOUT" }, resolve)
  );

  btn.disabled    = false;
  btn.textContent = "Sign out";
  _showOidcSignedOut();
  _showToast("Signed out of Warden Identity.", "success");
}

/**
 * Lock all editable fields and controls when the config comes from GPO.
 * Shows a read-only banner so users understand why they can't change settings.
 */
function _applyManagedLock() {
  // Disable all inputs and buttons the user would normally interact with
  ["gateway-url", "api-key", "tenant-id", "ollama-url"].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = true;
      el.style.cursor = "not-allowed";
      el.title = "Managed by IT policy — contact your administrator to change this.";
    }
  });

  ["save-btn", "test-btn", "toggle-btn"].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.disabled = true;
      el.style.display = "none";
    }
  });

  // Inject a lock banner at the top of the popup
  const banner = document.createElement("div");
  banner.id = "managed-banner";
  banner.style.cssText = [
    "background:#1a365d",
    "color:#bee3f8",
    "font-size:11px",
    "padding:6px 10px",
    "text-align:center",
    "border-radius:4px",
    "margin-bottom:8px",
  ].join(";");
  banner.innerHTML = "&#128274; Managed by IT policy";

  const body = document.body;
  body.insertBefore(banner, body.firstChild);
}

async function _saveConfig() {
  // Refuse saves in managed mode
  const cfg = await new Promise(resolve =>
    chrome.runtime.sendMessage({ type: "GET_CONFIG" }, resolve)
  );
  if (cfg.managed) {
    _showToast("Settings are managed by IT policy.", "error");
    return;
  }

  const gatewayUrl = document.getElementById("gateway-url").value.trim().replace(/\/$/, "");
  const apiKey     = document.getElementById("api-key").value.trim();
  const tenantId   = document.getElementById("tenant-id").value.trim() || "default";
  const ollamaUrl  = document.getElementById("ollama-url").value.trim() || "http://localhost:3000";

  // Allow save without API key when signed in via OIDC
  const authState = await new Promise(resolve =>
    chrome.runtime.sendMessage({ type: "GET_AUTH_STATE" }, resolve)
  );
  if (!gatewayUrl || (!apiKey && !authState?.signedIn)) {
    _showToast("Gateway URL required. Sign in with Google or enter an API key.", "error");
    return;
  }

  const saveBtn = document.getElementById("save-btn");
  saveBtn.disabled = true;
  saveBtn.textContent = "Saving…";

  await chrome.storage.sync.set({ gatewayUrl, apiKey, tenantId, ollamaUrl, enabled: true });

  _updateStatusUI(true, true);
  document.getElementById("tenant-display").textContent = tenantId;
  _showToast("Saved! Extension is now active.", "success");

  saveBtn.disabled = false;
  saveBtn.textContent = "Save & Connect";
}

// ── Stats (chrome.storage.local) ──────────────────────────────────────────────

async function _loadStats() {
  const stats = await chrome.storage.local.get(["blocksToday", "requestsToday"]);
  document.getElementById("blocks-today").textContent   = stats.blocksToday   ?? 0;
  document.getElementById("requests-today").textContent = stats.requestsToday ?? 0;
}

// ── Connection test ────────────────────────────────────────────────────────────

async function _testConnection() {
  const gatewayUrl = document.getElementById("gateway-url").value.trim().replace(/\/$/, "");
  const apiKey     = document.getElementById("api-key").value.trim();

  if (!gatewayUrl || !apiKey) {
    _showToast("Enter Gateway URL and API Key first.", "error");
    return;
  }

  const testBtn = document.getElementById("test-btn");
  testBtn.textContent = "Testing…";
  testBtn.disabled    = true;

  try {
    const resp = await fetch(`${gatewayUrl}/ext/health`, {
      method: "GET",
      headers: { "X-API-Key": apiKey },
    });

    if (resp.ok) {
      const data = await resp.json().catch(() => ({}));
      const version = data.version || "connected";
      _showToast(`✅ Connected! Shadow Warden ${version}`, "success");
    } else if (resp.status === 401) {
      _showToast("❌ Invalid API Key — check your key.", "error");
    } else {
      _showToast(`⚠️ Server returned ${resp.status}`, "error");
    }
  } catch (err) {
    _showToast(`❌ Cannot reach ${gatewayUrl} — check the URL.`, "error");
  } finally {
    testBtn.textContent = "Test Connection";
    testBtn.disabled    = false;
  }
}

// ── Enable / disable toggle ────────────────────────────────────────────────────

async function _toggleEnabled() {
  const cfg = await new Promise(resolve =>
    chrome.runtime.sendMessage({ type: "GET_CONFIG" }, resolve)
  );
  if (cfg.managed) {
    _showToast("Settings are managed by IT policy.", "error");
    return;
  }
  const newEnabled = !(cfg.enabled !== false);
  await chrome.storage.sync.set({ enabled: newEnabled });
  _updateStatusUI(newEnabled, !!cfg.apiKey);
}

// ── UI helpers ────────────────────────────────────────────────────────────────

function _updateStatusUI(enabled, configured) {
  const dot    = document.getElementById("status-dot");
  const text   = document.getElementById("status-text");
  const toggle = document.getElementById("toggle-btn");

  if (!configured) {
    dot.className = "dot warning";
    text.textContent = "Not configured";
    toggle.textContent = "Setup needed";
  } else if (enabled) {
    dot.className = "dot active";
    text.textContent = "Protected";
    toggle.textContent = "Disable";
  } else {
    dot.className = "dot inactive";
    text.textContent = "Disabled";
    toggle.textContent = "Enable";
  }
}

function _showToast(message, type) {
  const toast = document.getElementById("toast");
  toast.textContent = message;
  toast.className = `toast ${type}`;
  setTimeout(() => {
    toast.className = "toast";
  }, 4_000);
}

// ── Event listeners ───────────────────────────────────────────────────────────

document.getElementById("save-btn").addEventListener("click",        _saveConfig);
document.getElementById("test-btn").addEventListener("click",        _testConnection);
document.getElementById("toggle-btn").addEventListener("click",      _toggleEnabled);
document.getElementById("signin-google-btn").addEventListener("click", _handleGoogleSignIn);
document.getElementById("signout-btn").addEventListener("click",      _handleSignOut);
