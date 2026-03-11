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

// ── Config (chrome.storage.sync) ──────────────────────────────────────────────

async function _loadConfig() {
  const cfg = await chrome.storage.sync.get(null);

  document.getElementById("gateway-url").value = cfg.gatewayUrl || "";
  document.getElementById("api-key").value     = cfg.apiKey     || "";
  document.getElementById("tenant-id").value   = cfg.tenantId   || "default";

  _updateStatusUI(cfg.enabled !== false, !!cfg.apiKey);

  const tenantDisplay = document.getElementById("tenant-display");
  tenantDisplay.textContent = cfg.tenantId && cfg.apiKey
    ? cfg.tenantId
    : "Not configured";
}

async function _saveConfig() {
  const gatewayUrl = document.getElementById("gateway-url").value.trim().replace(/\/$/, "");
  const apiKey     = document.getElementById("api-key").value.trim();
  const tenantId   = document.getElementById("tenant-id").value.trim() || "default";

  if (!gatewayUrl || !apiKey) {
    _showToast("Gateway URL and API Key are required.", "error");
    return;
  }

  const saveBtn = document.getElementById("save-btn");
  saveBtn.disabled = true;
  saveBtn.textContent = "Saving…";

  await chrome.storage.sync.set({ gatewayUrl, apiKey, tenantId, enabled: true });

  _updateStatusUI(true, true);
  document.getElementById("tenant-display").textContent = tenantId;
  _showToast("✅ Saved! Extension is now active.", "success");

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
  const cfg = await chrome.storage.sync.get(["enabled"]);
  const newEnabled = !(cfg.enabled !== false);
  await chrome.storage.sync.set({ enabled: newEnabled });

  const hasKey = !!(await chrome.storage.sync.get("apiKey")).apiKey;
  _updateStatusUI(newEnabled, hasKey);
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
