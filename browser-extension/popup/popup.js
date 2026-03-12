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

  if (!gatewayUrl || !apiKey) {
    _showToast("Gateway URL and API Key are required.", "error");
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
    const resp = await fetch(`${gatewayUrl}/health`, {
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

document.getElementById("save-btn").addEventListener("click",   _saveConfig);
document.getElementById("test-btn").addEventListener("click",   _testConnection);
document.getElementById("toggle-btn").addEventListener("click", _toggleEnabled);
