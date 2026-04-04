/**
 * popup.js — Shadow Warden AI Extension Popup
 *
 * Handles:
 *  - Tab navigation (Settings | Impact)
 *  - Loading and saving config to chrome.storage.sync
 *  - Displaying today's block/request stats from chrome.storage.local
 *  - Enable/disable toggle
 *  - Connection test (POST /health to Shadow Warden)
 *  - Dollar Impact tab: fetches GET /tenant/impact via background SW,
 *    renders KPI cards, SVG sparkline, threat breakdown, quota bar
 */

// ── Load state on popup open ──────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", async () => {
  _initTabs();
  await _loadConfig();
  await _loadStats();
  await _loadAuthState();
});

// ── Tab navigation ────────────────────────────────────────────────────────────

function _initTabs() {
  document.querySelectorAll(".tab-btn").forEach(btn => {
    btn.addEventListener("click", () => {
      const tab = btn.dataset.tab;

      // Update active button
      document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
      btn.classList.add("active");

      // Update active panel
      document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
      document.getElementById(`panel-${tab}`).classList.add("active");

      // Lazy-load impact data when user switches to Impact tab
      if (tab === "impact") {
        _loadImpact();
      }
    });
  });
}

// ── Config (managed > sync > defaults) ───────────────────────────────────────

async function _loadConfig() {
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

  const configSection = document.getElementById("config-section");
  if (configSection) configSection.style.opacity = "0.5";

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

function _applyManagedLock() {
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
  setTimeout(() => { toast.className = "toast"; }, 4_000);
}

// ── Dollar Impact tab ─────────────────────────────────────────────────────────

let _impactLoaded = false;

async function _loadImpact(force = false) {
  if (_impactLoaded && !force) return;

  const loading = document.getElementById("impact-loading");
  const content = document.getElementById("impact-content");
  const errEl   = document.getElementById("impact-error");

  loading.style.display = "block";
  content.style.display = "none";
  errEl.style.display   = "none";

  const data = await new Promise(resolve =>
    chrome.runtime.sendMessage({ type: "GET_TENANT_IMPACT", period: 30 }, resolve)
  );

  loading.style.display = "none";

  if (!data || data.error) {
    errEl.textContent   = data?.error || "Unable to load impact data. Check your connection.";
    errEl.style.display = "block";
    return;
  }

  _renderImpact(data);
  _impactLoaded = true;
}

function _fmt$(n) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `$${(n / 1_000).toFixed(1)}K`;
  return `$${Math.round(n).toLocaleString()}`;
}

function _fmtNum(n) {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function _renderImpact(d) {
  const content = document.getElementById("impact-content");
  content.style.display = "block";

  // Annual projection banner
  document.getElementById("impact-annual").textContent = _fmt$(d.annual_projection || 0);

  // KPI cards
  document.getElementById("impact-dollar-saved").textContent = _fmt$(d.dollar_saved || 0);
  document.getElementById("impact-blocked").textContent      = _fmtNum(d.requests_blocked || 0);
  document.getElementById("impact-pii").textContent          = _fmtNum(d.pii_masked || 0);

  // Sparkline (last 14 days of timeline)
  const timeline = (d.timeline || []).slice(-14);
  _renderSparkline(timeline);

  // Top threats
  _renderThreats(d.top_threats || []);

  // Plan badge + quota bar
  const plan      = d.plan || "free";
  const quota     = d.quota;
  const rateLimit = d.rate_limit_per_min || 10;
  const usedPct   = d.quota_used_pct || 0;
  const total     = d.requests_total || 0;

  document.getElementById("badge-plan").textContent = plan.toUpperCase();
  document.getElementById("badge-rate").textContent = `${rateLimit}/min`;

  const bar = document.getElementById("quota-bar");
  bar.style.width = `${Math.min(usedPct, 100)}%`;
  bar.className   = "quota-bar" + (usedPct >= 90 ? " danger" : usedPct >= 70 ? " warn" : "");

  const quotaLabel = quota
    ? `${_fmtNum(total)} / ${_fmtNum(quota)} requests`
    : `${_fmtNum(total)} requests (unlimited)`;
  document.getElementById("quota-used-label").textContent = quotaLabel;
  document.getElementById("quota-pct-label").textContent  = quota
    ? `${usedPct.toFixed(1)}%`
    : "∞";

  // Last updated
  const now = new Date();
  document.getElementById("impact-last-updated").textContent =
    `Updated ${now.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

function _renderSparkline(timeline) {
  // timeline: [{date, requests, blocked, pii}, ...]
  const W = 308, H = 44, PAD = 3;
  const values = timeline.map(b => b.blocked || 0);
  const max    = Math.max(...values, 1);
  const n      = values.length;

  if (n < 2) {
    document.getElementById("sparkline-line").setAttribute("points", "");
    document.getElementById("sparkline-fill").setAttribute("points", "");
    return;
  }

  const pts = values.map((v, i) => {
    const x = PAD + (i / (n - 1)) * (W - PAD * 2);
    const y = PAD + (1 - v / max) * (H - PAD * 2);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  document.getElementById("sparkline-line").setAttribute("points", pts.join(" "));

  // Closed polygon for the gradient fill
  const firstX = PAD;
  const lastX  = PAD + (W - PAD * 2);
  const fillPts = [
    `${firstX.toFixed(1)},${H}`,
    ...pts,
    `${lastX.toFixed(1)},${H}`,
  ];
  document.getElementById("sparkline-fill").setAttribute("points", fillPts.join(" "));
}

function _renderThreats(threats) {
  const list = document.getElementById("threats-list");
  list.innerHTML = "";

  const top5 = threats.slice(0, 5);
  if (top5.length === 0) {
    list.innerHTML = '<div style="font-size:12px;color:#4b5563;padding:4px 0">No threats blocked in this period.</div>';
    return;
  }

  const maxCount = top5[0].count || 1;
  top5.forEach(t => {
    const row = document.createElement("div");
    row.className = "threat-row";
    const barPct = Math.round((t.count / maxCount) * 100);
    row.innerHTML = `
      <span class="threat-label">${_esc(t.label)}</span>
      <div class="threat-bar-wrap">
        <div class="threat-bar" style="width:${barPct}%"></div>
      </div>
      <span class="threat-count">${t.count}</span>
    `;
    list.appendChild(row);
  });
}

function _esc(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// ── Event listeners ───────────────────────────────────────────────────────────

document.getElementById("save-btn").addEventListener("click",           _saveConfig);
document.getElementById("test-btn").addEventListener("click",           _testConnection);
document.getElementById("toggle-btn").addEventListener("click",         _toggleEnabled);
document.getElementById("signin-google-btn").addEventListener("click",  _handleGoogleSignIn);
document.getElementById("signout-btn").addEventListener("click",        _handleSignOut);
document.getElementById("impact-refresh-btn").addEventListener("click", () => {
  _impactLoaded = false;
  _loadImpact(true);
});
