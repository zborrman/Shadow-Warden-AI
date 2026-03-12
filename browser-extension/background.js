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
});

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
});

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
