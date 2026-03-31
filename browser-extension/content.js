/**
 * content.js — Shadow Warden AI Fetch Interceptor
 * world: "MAIN" — runs in the page's own JS context
 *
 * Three-tier response handling matching data_policy.py classifications:
 *
 *   🔴 RED (data_class="red" or PII/HIGH risk)
 *      → Hard block. Full-screen overlay. No bypass. Telegram alert sent.
 *
 *   🟡 YELLOW (data_class="yellow", internal data sent to cloud AI)
 *      → Advisory overlay. Two options:
 *           [Send to Local AI]  — copies prompt + opens Ollama/LM Studio
 *           [Cancel]           — dismisses, user edits prompt themselves
 *      → NOT sent to cloud LLM. Soft desktop notification.
 *
 *   🟢 GREEN (allowed=true, no advisory)
 *      → Pass-through. Brief toast if data_class="yellow" but cloud allowed.
 *
 * Fail-open policy: if Warden gateway is unreachable, request passes through.
 */

(function () {
  "use strict";

  // ── Config ────────────────────────────────────────────────────────────────

  let _cfg = {
    gatewayUrl:  "http://localhost:8001",
    apiKey:      "",
    tenantId:    "default",
    enabled:     true,
    ollamaUrl:   "http://localhost:3000",   // Open WebUI or LM Studio
  };

  function _loadConfig() {
    try {
      chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (cfg) => {
        if (cfg && !chrome.runtime.lastError) Object.assign(_cfg, cfg);
      });
    } catch (_) {}
  }
  _loadConfig();
  setInterval(_loadConfig, 30_000);

  // ── AI endpoint matchers ──────────────────────────────────────────────────

  const AI_ENDPOINTS = [
    { test: (url) => url.includes("chatgpt.com/backend-api/conversation") ||
                     url.includes("chat.openai.com/backend-api/conversation"),
      extract: _extractOpenAI },
    { test: (url) => url.includes("claude.ai/api/") && url.includes("completion"),
      extract: _extractClaude },
    { test: (url) => url.includes("gemini.google.com") && url.includes("StreamGenerate"),
      extract: _extractGemini },
    { test: (url) => url.includes("copilot.microsoft.com/c/api/chat"),
      extract: _extractCopilot },
  ];

  // ── Prompt extraction ──────────────────────────────────────────────────────

  function _extractOpenAI(body) {
    const msgs = body?.messages || [];
    const parts = [];
    for (const m of msgs) {
      if (typeof m.content === "string") {
        parts.push(m.content);
      } else if (Array.isArray(m.content)) {
        for (const c of m.content) {
          if (c?.text)  parts.push(c.text);
          else if (c?.parts) parts.push(...c.parts.filter(p => typeof p === "string"));
        }
      }
    }
    return parts.join("\n");
  }

  function _extractClaude(body) {
    if (body?.prompt) return body.prompt;
    return _extractOpenAI(body);
  }

  function _extractGemini(body) {
    if (typeof body === "string") {
      const m = body.match(/"([^"]{20,})"/);
      return m ? m[1] : body.slice(0, 2000);
    }
    return JSON.stringify(body).slice(0, 2000);
  }

  function _extractCopilot(body) {
    return body?.message || _extractOpenAI(body);
  }

  // ── Main fetch interceptor ─────────────────────────────────────────────────

  const _origFetch = window.fetch.bind(window);

  window.fetch = async function (...args) {
    if (!_cfg.enabled || !_cfg.apiKey) return _origFetch(...args);

    const [resource, init] = args;
    const url = typeof resource === "string" ? resource
              : resource instanceof URL      ? resource.href
              : resource?.url ?? "";

    const matcher = AI_ENDPOINTS.find(m => m.test(url));
    if (!matcher) return _origFetch(...args);

    let bodyObj = null;
    try {
      const rawBody = init?.body;
      if (typeof rawBody === "string") bodyObj = JSON.parse(rawBody);
      else if (rawBody instanceof FormData || rawBody instanceof URLSearchParams)
        return _origFetch(...args);
    } catch (_) {
      return _origFetch(...args);
    }

    const promptText = matcher.extract(bodyObj)?.trim();
    if (!promptText || promptText.length < 5) return _origFetch(...args);

    // ── Call Shadow Warden /filter ─────────────────────────────────────────
    let wardenResult = null;
    let wardenStatus = 200;

    try {
      const wardenResp = await _origFetch(`${_cfg.gatewayUrl}/ext/filter`, {
        method:  "POST",
        headers: {
          "Content-Type": "application/json",
          "X-API-Key":    _cfg.apiKey,
        },
        body: JSON.stringify({
          content:   promptText,
          tenant_id: _cfg.tenantId,
          context: {
            source:   "browser_extension",
            site:     new URL(url).hostname,
            provider: _siteToProvider(url),
          },
        }),
      });

      wardenStatus = wardenResp.status;
      const body = await wardenResp.json().catch(() => ({}));

      if (wardenStatus === 403) {
        // Data policy block — detail contains data_class + reason + suggestion
        const detail = body?.detail || body;
        wardenResult = {
          allowed:    false,
          data_class: detail?.data_class || "red",
          reason:     detail?.reason     || "Content blocked by policy.",
          suggestion: detail?.suggestion || "",
          risk_level: "block",
          flags:      [],
        };
      } else if (wardenStatus === 401 || wardenStatus === 402) {
        // Auth or quota — fail-open (don't break the user's work)
        console.warn("[Shadow Warden] Gateway returned", wardenStatus);
        return _origFetch(...args);
      } else if (!wardenResp.ok) {
        console.warn("[Shadow Warden] Server error", wardenStatus);
        return _origFetch(...args);
      } else {
        wardenResult = body;
      }
    } catch (err) {
      console.warn("[Shadow Warden] Gateway unreachable:", err.message);
      return _origFetch(...args);   // fail-open
    }

    // ── Decision routing ───────────────────────────────────────────────────

    if (!wardenResult.allowed) {
      const site      = new URL(url).hostname;
      const dataClass = wardenResult.data_class || "red";
      const riskLevel = wardenResult.risk_level || "high";
      const reason    = wardenResult.reason     || "Confidential data detected.";
      const suggestion = wardenResult.suggestion || "";

      if (dataClass === "yellow") {
        // ── YELLOW: advisory overlay — user chooses ──────────────────────
        return _handleYellow({ promptText, reason, suggestion, site, args });
      } else {
        // ── RED / PII / HIGH: hard block ─────────────────────────────────
        _showBlockOverlay({ riskLevel, dataClass, reason, suggestion, site });
        _notifyBackground({ tenantId: _cfg.tenantId, riskLevel, dataClass, reason, site });
        return new Response(
          JSON.stringify({ error: "Shadow Warden AI: Request blocked.", reason }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        );
      }
    }

    // ── Advisory toast for YELLOW-but-allowed (block_cloud_yellow=false) ──
    if (wardenResult.data_class === "yellow") {
      _showAdvisoryToast(wardenResult.reason || "Internal data detected — consider using local AI.");
    }

    return _origFetch(...args);
  };

  // ── YELLOW handler — advisory overlay with Ollama redirect ────────────────

  function _handleYellow({ promptText, reason, suggestion, site, args }) {
    // Returns a Promise that resolves to either:
    //  - a cancelled Response (user chose "redirect to local AI" or "cancel")
    //  - the original fetch result (user chose "send anyway" — admin configurable)
    return new Promise((resolve) => {
      document.getElementById("sw-yellow-overlay")?.remove();

      const overlay = document.createElement("div");
      overlay.id = "sw-yellow-overlay";
      overlay.style.cssText = `
        position: fixed; top: 0; left: 0; right: 0; bottom: 0;
        background: rgba(0,0,0,0.7); z-index: 2147483647;
        display: flex; align-items: center; justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        animation: sw-fade 0.2s ease;
      `;

      const previewText = promptText.length > 200
        ? promptText.slice(0, 200) + "…"
        : promptText;

      overlay.innerHTML = `
        <style>
          @keyframes sw-fade { from { opacity:0; transform:scale(0.96) } to { opacity:1; transform:scale(1) } }
          #sw-yellow-card {
            background: #1a1a2e; border: 2px solid #f59e0b; border-radius: 16px;
            padding: 28px; max-width: 520px; width: 92%; color: #fff;
            box-shadow: 0 25px 60px rgba(0,0,0,0.6);
          }
          #sw-yellow-card .yw-header {
            display: flex; align-items: center; gap: 12px; margin-bottom: 14px;
          }
          #sw-yellow-card .yw-emoji { font-size: 36px; }
          #sw-yellow-card .yw-title { font-size: 17px; font-weight: 700; color: #fbbf24; }
          #sw-yellow-card .yw-sub { font-size: 12px; color: #6b7280; margin-top: 2px; }
          #sw-yellow-card .yw-reason {
            background: #111827; border-radius: 8px; padding: 12px; margin-bottom: 14px;
            font-size: 13px; color: #d1d5db; line-height: 1.5;
          }
          #sw-yellow-card .yw-preview {
            background: #0f1a2e; border: 1px solid #1e3a5f; border-radius: 8px;
            padding: 10px; margin-bottom: 16px; font-size: 12px; color: #93c5fd;
            font-family: monospace; max-height: 80px; overflow: hidden;
            white-space: pre-wrap; word-break: break-word;
          }
          #sw-yellow-card .yw-suggestion {
            background: #0c2340; border-radius: 8px; padding: 10px 12px;
            font-size: 12px; color: #7dd3fc; margin-bottom: 18px;
          }
          #sw-yellow-card .yw-actions { display: flex; gap: 10px; flex-wrap: wrap; }
          .yw-btn {
            flex: 1; border-radius: 8px; padding: 10px 14px; font-size: 13px;
            font-weight: 600; cursor: pointer; border: none; min-width: 120px;
            transition: opacity 0.15s;
          }
          .yw-btn:hover { opacity: 0.85; }
          .yw-btn-ollama { background: #7c3aed; color: #fff; }
          .yw-btn-cancel { background: transparent; color: #9ca3af;
            border: 1px solid #374151; flex: 0; }
        </style>
        <div id="sw-yellow-card">
          <div class="yw-header">
            <span class="yw-emoji">🟡</span>
            <div>
              <div class="yw-title">Internal Data Detected</div>
              <div class="yw-sub">Shadow Warden AI · ${_escapeHtml(site)}</div>
            </div>
          </div>
          <div class="yw-reason">${_escapeHtml(reason)}</div>
          <div class="yw-preview">${_escapeHtml(previewText)}</div>
          ${suggestion ? `<div class="yw-suggestion">💡 ${_escapeHtml(suggestion)}</div>` : ""}
          <div class="yw-actions">
            <button class="yw-btn yw-btn-ollama" id="yw-local-btn">
              🦙 Send to Local AI (Ollama)
            </button>
            <button class="yw-btn yw-btn-cancel" id="yw-cancel-btn">Cancel</button>
          </div>
        </div>
      `;

      document.body.appendChild(overlay);

      // ── "Send to Local AI" ────────────────────────────────────────────
      overlay.querySelector("#yw-local-btn").addEventListener("click", async () => {
        overlay.remove();
        await _redirectToLocalAI(promptText);
        // Return a "cancelled" response so the cloud fetch does NOT proceed
        resolve(new Response(
          JSON.stringify({ error: "Redirected to local AI by Shadow Warden.", redirected: true }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // ── "Cancel" ──────────────────────────────────────────────────────
      overlay.querySelector("#yw-cancel-btn").addEventListener("click", () => {
        overlay.remove();
        resolve(new Response(
          JSON.stringify({ error: "Request cancelled by Shadow Warden." }),
          { status: 200, headers: { "Content-Type": "application/json" } }
        ));
      });

      // ESC key dismiss = cancel
      const onKey = (e) => {
        if (e.key === "Escape") {
          overlay.remove();
          document.removeEventListener("keydown", onKey);
          resolve(new Response("", { status: 200 }));
        }
      };
      document.addEventListener("keydown", onKey);
    });
  }

  // ── Redirect to local AI (Ollama / LM Studio / Open WebUI) ───────────────

  async function _redirectToLocalAI(promptText) {
    // 1. Copy prompt to clipboard so user can paste into local model UI
    try {
      await navigator.clipboard.writeText(promptText);
    } catch (_) {
      // Clipboard may fail without user gesture in some browsers — silent
    }

    // 2. Open local AI web UI in new tab
    //    Open WebUI (Ollama frontend): typically http://localhost:3000
    //    LM Studio: http://localhost:1234
    const localUrl = _cfg.ollamaUrl || "http://localhost:3000";
    try {
      window.open(localUrl, "_blank", "noopener");
    } catch (_) {}

    // 3. Show brief toast confirming action
    _showAdvisoryToast(
      "📋 Prompt copied to clipboard — Local AI opening in new tab.",
      "#7c3aed",
      5000
    );

    // 4. Notify background for stats
    _notifyBackground({
      tenantId:  _cfg.tenantId,
      riskLevel: "medium",
      dataClass: "yellow",
      reason:    "Redirected to local AI",
      site:      location.hostname,
    });
  }

  // ── Hard block overlay (RED / PII) ────────────────────────────────────────

  function _showBlockOverlay({ riskLevel, dataClass, reason, suggestion, site }) {
    document.getElementById("sw-block-overlay")?.remove();

    const emoji = { low: "🟡", medium: "🟠", high: "🔴", block: "🚫" }[riskLevel] || "🚫";
    const color = { low: "#f59e0b", medium: "#f97316", high: "#ef4444", block: "#dc2626" }[riskLevel] || "#dc2626";

    const overlay = document.createElement("div");
    overlay.id = "sw-block-overlay";
    overlay.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.8); z-index: 2147483647;
      display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      animation: sw-fade-in 0.2s ease;
    `;

    overlay.innerHTML = `
      <style>
        @keyframes sw-fade-in { from { opacity:0; transform:scale(0.95) } to { opacity:1; transform:scale(1) } }
        #sw-block-card {
          background: #1a1a2e; border: 2px solid ${color}; border-radius: 16px;
          padding: 32px; max-width: 480px; width: 90%; color: #fff;
          text-align: center; box-shadow: 0 25px 60px rgba(0,0,0,0.5);
        }
        #sw-block-card h2   { margin: 0 0 8px; font-size: 22px; color: ${color}; }
        #sw-block-card .emoji { font-size: 48px; margin-bottom: 12px; display: block; }
        #sw-block-card .badge {
          background: ${color}22; border: 1px solid ${color}55;
          color: ${color}; border-radius: 6px; padding: 4px 10px;
          font-size: 12px; font-weight: 600; display: inline-block;
          margin-bottom: 16px; letter-spacing: 0.05em;
        }
        #sw-block-card p { color: #ccc; font-size: 15px; line-height: 1.5; margin: 0 0 12px; }
        #sw-block-card .suggestion {
          background: #0f3460; border-radius: 8px; padding: 12px;
          color: #93c5fd; font-size: 13px; margin-top: 8px; text-align: left;
        }
        #sw-block-dismiss {
          background: transparent; border: 1px solid #555; color: #aaa;
          border-radius: 8px; padding: 10px 24px; cursor: pointer;
          font-size: 14px; margin-top: 20px;
        }
        #sw-block-dismiss:hover { border-color: #aaa; color: #fff; }
      </style>
      <div id="sw-block-card">
        <span class="emoji">${emoji}</span>
        <div class="badge">SHADOW WARDEN AI · ${riskLevel.toUpperCase()}</div>
        <h2>Transmission Blocked</h2>
        <p>${_escapeHtml(reason)}</p>
        ${suggestion ? `<div class="suggestion">💡 ${_escapeHtml(suggestion)}</div>` : ""}
        <button id="sw-block-dismiss">Dismiss</button>
      </div>
    `;

    document.body.appendChild(overlay);

    const dismiss = () => overlay.remove();
    overlay.querySelector("#sw-block-dismiss").addEventListener("click", dismiss);
    setTimeout(dismiss, 10_000);
    overlay.addEventListener("click", (e) => { if (e.target === overlay) dismiss(); });
  }

  // ── Advisory toast (GREEN with YELLOW hint, or redirect confirmation) ─────

  function _showAdvisoryToast(message, bgColor = "#78350f", duration = 4000) {
    document.getElementById("sw-toast")?.remove();

    const toast = document.createElement("div");
    toast.id = "sw-toast";
    toast.style.cssText = `
      position: fixed; bottom: 24px; right: 24px;
      background: ${bgColor}; color: #fff;
      border-radius: 10px; padding: 12px 18px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 13px; line-height: 1.4; max-width: 320px;
      z-index: 2147483647; box-shadow: 0 8px 24px rgba(0,0,0,0.4);
      animation: sw-slide-in 0.25s ease;
    `;

    const style = document.createElement("style");
    style.textContent = "@keyframes sw-slide-in { from { opacity:0; transform:translateY(12px) } to { opacity:1; transform:translateY(0) } }";
    toast.appendChild(style);

    const text = document.createElement("div");
    text.textContent = message;
    toast.appendChild(text);

    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), duration);
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  function _notifyBackground(data) {
    try {
      chrome.runtime.sendMessage({ type: "WARDEN_BLOCK", data });
    } catch (_) {}
  }

  function _siteToProvider(url) {
    if (url.includes("openai") || url.includes("chatgpt")) return "openai";
    if (url.includes("claude"))  return "anthropic";
    if (url.includes("gemini"))  return "google";
    if (url.includes("copilot")) return "azure";
    return "unknown";
  }

  function _escapeHtml(str) {
    return String(str || "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

})();
