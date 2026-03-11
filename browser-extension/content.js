/**
 * content.js — Shadow Warden AI Fetch Interceptor
 * world: "MAIN" — runs in the page's own JS context (not isolated)
 *
 * Intercepts window.fetch() calls to AI chat APIs before they leave the browser.
 * Sends the prompt text to Shadow Warden /filter for analysis.
 * On BLOCK: cancels the request and shows a non-intrusive overlay.
 *
 * Supported sites and their chat API endpoints:
 *   chatgpt.com / chat.openai.com  → /backend-api/conversation
 *   claude.ai                       → /api/organizations/*/chat_conversations/*/completion
 *   gemini.google.com               → /_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate
 *   copilot.microsoft.com           → /c/api/chat
 */

(function () {
  "use strict";

  // ── Config (loaded async from background) ──────────────────────────────────

  let _cfg = {
    gatewayUrl:  "http://localhost:8001",
    apiKey:      "",
    tenantId:    "default",
    enabled:     true,
  };

  // Load config from background service worker
  function _loadConfig() {
    try {
      chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (cfg) => {
        if (cfg && !chrome.runtime.lastError) {
          Object.assign(_cfg, cfg);
        }
      });
    } catch (_) {
      // Extension context invalidated (page reload during update) — ignore
    }
  }
  _loadConfig();
  // Refresh config every 30s in case it changed in popup
  setInterval(_loadConfig, 30_000);

  // ── URL matchers for each AI chat site ────────────────────────────────────

  const AI_ENDPOINTS = [
    // ChatGPT
    { test: (url) => url.includes("chatgpt.com/backend-api/conversation") ||
                     url.includes("chat.openai.com/backend-api/conversation"),
      extract: _extractOpenAI },
    // Claude
    { test: (url) => url.includes("claude.ai/api/") && url.includes("completion"),
      extract: _extractClaude },
    // Gemini
    { test: (url) => url.includes("gemini.google.com") && url.includes("StreamGenerate"),
      extract: _extractGemini },
    // Copilot
    { test: (url) => url.includes("copilot.microsoft.com/c/api/chat"),
      extract: _extractCopilot },
  ];

  // ── Prompt extraction per provider ────────────────────────────────────────

  function _extractOpenAI(body) {
    // messages[].content is either a string or array of {type, text/parts}
    const msgs = body?.messages || [];
    const parts = [];
    for (const m of msgs) {
      if (typeof m.content === "string") parts.push(m.content);
      else if (Array.isArray(m.content)) {
        for (const c of m.content) {
          if (c?.text) parts.push(c.text);
          else if (c?.parts) parts.push(...c.parts.filter(p => typeof p === "string"));
        }
      }
    }
    return parts.join("\n");
  }

  function _extractClaude(body) {
    // {"prompt": "Human: ...\n\nAssistant:"} or messages[] format
    if (body?.prompt) return body.prompt;
    return _extractOpenAI(body);   // Claude API v2 uses same messages[] format
  }

  function _extractGemini(body) {
    // Gemini uses a nested f.req format; best-effort extraction
    if (typeof body === "string") {
      const match = body.match(/"([^"]{20,})"/);
      return match ? match[1] : body.slice(0, 2000);
    }
    return JSON.stringify(body).slice(0, 2000);
  }

  function _extractCopilot(body) {
    return body?.message || _extractOpenAI(body);
  }

  // ── Main fetch interceptor ────────────────────────────────────────────────

  const _origFetch = window.fetch.bind(window);

  window.fetch = async function (...args) {
    // Bypass if extension disabled
    if (!_cfg.enabled || !_cfg.apiKey) {
      return _origFetch(...args);
    }

    const [resource, init] = args;
    const url = typeof resource === "string" ? resource
              : resource instanceof URL      ? resource.href
              : resource?.url ?? "";

    // Find matching AI endpoint
    const matcher = AI_ENDPOINTS.find(m => m.test(url));
    if (!matcher) {
      return _origFetch(...args);
    }

    // Parse request body
    let bodyObj = null;
    try {
      const rawBody = init?.body;
      if (typeof rawBody === "string") {
        bodyObj = JSON.parse(rawBody);
      } else if (rawBody instanceof FormData || rawBody instanceof URLSearchParams) {
        return _origFetch(...args);   // skip multipart (file uploads)
      }
    } catch (_) {
      return _origFetch(...args);   // body not JSON — skip
    }

    // Extract prompt text
    const promptText = matcher.extract(bodyObj)?.trim();
    if (!promptText || promptText.length < 5) {
      return _origFetch(...args);   // too short to analyze
    }

    // Call Shadow Warden /filter
    let wardenResult;
    try {
      const wardenResp = await _origFetch(`${_cfg.gatewayUrl}/filter`, {
        method:  "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key":    _cfg.apiKey,
        },
        body: JSON.stringify({
          content:   promptText,
          tenant_id: _cfg.tenantId,
          context:   {
            source:   "browser_extension",
            site:     new URL(url).hostname,
            provider: _siteToProvider(url),
          },
        }),
      });

      if (!wardenResp.ok) {
        // Auth failure or server error — fail-open (don't block user)
        console.warn("[Shadow Warden] Filter API error:", wardenResp.status);
        return _origFetch(...args);
      }

      wardenResult = await wardenResp.json();
    } catch (err) {
      // Network error (Hetzner unreachable) — fail-open
      console.warn("[Shadow Warden] Gateway unreachable:", err.message);
      return _origFetch(...args);
    }

    // ── Decision ──────────────────────────────────────────────────────────
    if (!wardenResult.allowed) {
      const site      = new URL(url).hostname;
      const riskLevel = wardenResult.risk_level || "high";
      const dataClass = wardenResult.flags?.find(f => f.flag === "PII_DETECTED")
                        ? "pii" : "policy";
      const reason    = wardenResult.reason || "Confidential data detected.";
      const suggestion = wardenResult.suggestion || "";

      // Show blocking overlay
      _showBlockOverlay({ riskLevel, reason, suggestion, site });

      // Notify background (for stats + desktop notification)
      try {
        chrome.runtime.sendMessage({
          type: "WARDEN_BLOCK",
          data: { tenantId: _cfg.tenantId, riskLevel, dataClass, reason, site },
        });
      } catch (_) {}

      // Cancel the original fetch — return a fake aborted response
      return new Response(
        JSON.stringify({ error: "Shadow Warden AI: Request blocked.", reason }),
        {
          status:  403,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    // Allowed — pass through unchanged
    return _origFetch(...args);
  };

  // ── Block overlay UI ──────────────────────────────────────────────────────

  function _showBlockOverlay({ riskLevel, reason, suggestion, site }) {
    // Remove any existing overlay
    document.getElementById("sw-block-overlay")?.remove();

    const emoji  = { low: "🟡", medium: "🟠", high: "🔴", block: "🚫" }[riskLevel] || "🚫";
    const color  = { low: "#f59e0b", medium: "#f97316", high: "#ef4444", block: "#dc2626" }[riskLevel] || "#dc2626";

    const overlay = document.createElement("div");
    overlay.id = "sw-block-overlay";
    overlay.style.cssText = `
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.75);
      z-index: 2147483647;
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      animation: sw-fade-in 0.2s ease;
    `;

    overlay.innerHTML = `
      <style>
        @keyframes sw-fade-in { from { opacity: 0; transform: scale(0.95); } to { opacity: 1; transform: scale(1); } }
        #sw-block-card { background: #1a1a2e; border: 2px solid ${color}; border-radius: 16px;
          padding: 32px; max-width: 480px; width: 90%; color: #fff; text-align: center; box-shadow: 0 25px 60px rgba(0,0,0,0.5); }
        #sw-block-card h2 { margin: 0 0 8px; font-size: 22px; color: ${color}; }
        #sw-block-card .emoji { font-size: 48px; margin-bottom: 12px; display: block; }
        #sw-block-card .badge { background: ${color}22; border: 1px solid ${color}55;
          color: ${color}; border-radius: 6px; padding: 4px 10px; font-size: 12px;
          font-weight: 600; display: inline-block; margin-bottom: 16px; letter-spacing: 0.05em; }
        #sw-block-card p { color: #ccc; font-size: 15px; line-height: 1.5; margin: 0 0 12px; }
        #sw-block-card .suggestion { background: #0f3460; border-radius: 8px; padding: 12px;
          color: #93c5fd; font-size: 13px; margin-top: 8px; text-align: left; }
        #sw-block-card .site-tag { color: #6b7280; font-size: 12px; margin-bottom: 20px; }
        #sw-block-dismiss { background: transparent; border: 1px solid #555; color: #aaa;
          border-radius: 8px; padding: 10px 24px; cursor: pointer; font-size: 14px; margin-top: 20px; }
        #sw-block-dismiss:hover { border-color: #aaa; color: #fff; }
      </style>
      <div id="sw-block-card">
        <span class="emoji">${emoji}</span>
        <div class="badge">SHADOW WARDEN AI · ${riskLevel.toUpperCase()}</div>
        <h2>Transmission Blocked</h2>
        <p class="site-tag">Intercepted on ${site}</p>
        <p>${_escapeHtml(reason)}</p>
        ${suggestion ? `<div class="suggestion">💡 ${_escapeHtml(suggestion)}</div>` : ""}
        <button id="sw-block-dismiss">Dismiss</button>
      </div>
    `;

    document.body.appendChild(overlay);

    // Auto-dismiss after 8 seconds, or on button click
    const dismiss = () => overlay.remove();
    overlay.querySelector("#sw-block-dismiss")?.addEventListener("click", dismiss);
    setTimeout(dismiss, 8_000);
    // Also dismiss if user clicks outside the card
    overlay.addEventListener("click", (e) => {
      if (e.target === overlay) dismiss();
    });
  }

  // ── Utilities ─────────────────────────────────────────────────────────────

  function _siteToProvider(url) {
    if (url.includes("openai") || url.includes("chatgpt")) return "openai";
    if (url.includes("claude"))   return "anthropic";
    if (url.includes("gemini"))   return "google";
    if (url.includes("copilot"))  return "azure";
    return "unknown";
  }

  function _escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

})();
