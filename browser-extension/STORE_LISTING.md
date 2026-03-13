# Chrome Web Store — Listing Copy
# Shadow Warden AI

> Internal document. Copy-paste each section into the corresponding
> field in the Chrome Web Store Developer Dashboard.
> Last updated: 2026-03-13

---

## Basic Information

**Extension Name** (max 75 chars):
```
Shadow Warden AI — AI Data Loss Prevention
```

**Short Description** (max 132 chars — shown in search results):
```
Stops confidential data and PII from reaching ChatGPT, Claude, Gemini & Copilot. Works with your on-premise gateway.
```
*(117 chars)*

**Category:** Productivity

**Language:** English (United States)

---

## Detailed Description

*(Up to 16 000 chars. Plain text only. No HTML. Shown on the extension's store page.)*

```
Shadow Warden AI intercepts outbound prompts on your company's AI tools — ChatGPT, Claude, Gemini, and Microsoft Copilot — and evaluates them against your organisation's data-protection policy before they leave your browser.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
HOW IT WORKS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

When you press Send on a supported AI platform, Shadow Warden silently:

1. Extracts the prompt text from the outgoing request.
2. Forwards it to your organisation's Shadow Warden AI gateway — a server running on your own infrastructure (or on your local machine).
3. Receives a security decision in real time (typically under 50 ms).
4. Either passes the request through, shows an advisory, or blocks transmission — all before the prompt reaches any cloud AI service.

If the gateway is unreachable, the extension fails open and does not interrupt your work.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THREE-TIER RESPONSE SYSTEM
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🔴 RED (Hard Block)
Prompt contains classified, legally privileged, or highly sensitive content (credentials, patient data, source code classified RED by your policy). The request is stopped immediately. A full-screen overlay explains the reason. A Telegram / Slack alert is sent to your security team.

🟡 YELLOW (Advisory)
Prompt contains internal business information your policy flags as requiring caution. An overlay appears with two choices:
  • Send to Local AI (Ollama / LM Studio) — your prompt is copied to the clipboard and a local AI opens in a new tab, so you can get an answer without sending data to the cloud.
  • Cancel — the request is cancelled; you can edit the prompt and try again.

🟢 GREEN
Prompt passes all checks. The original request is forwarded to the AI service without modification. No visible interruption.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT IS DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The Shadow Warden AI gateway detects:

• PII: email addresses, phone numbers, national ID numbers, passport numbers, IBAN / credit-card numbers
• Credentials & secrets: API keys (OpenAI, AWS, GitHub, HuggingFace, Anthropic), passwords, tokens
• Jailbreak attempts: prompt injection, indirect injection, role-play attacks, encoded payloads (Base64, Hex, ROT13, Unicode homoglyphs)
• Policy violations: terms defined by your IT administrator (e.g. company financial data, M&A code names, patient identifiers)

Detection runs on your own infrastructure — no content leaves your network for analysis.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ZERO-CONTENT LOGGING
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The gateway never writes prompt text to disk. Only metadata is logged:
  • Timestamp and tenant identifier
  • Risk classification (low / medium / high / block)
  • Entity type labels only (e.g. "EMAIL", "PHONE") — never the actual values
  • Processing latency

This design satisfies GDPR Article 25 (data minimisation by design and by default).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ENTERPRISE DEPLOYMENT (MSP / IT ADMINS)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Shadow Warden AI supports zero-touch enterprise deployment:

• Windows Group Policy (GPO) / Microsoft Intune — push gateway URL, API key, and tenant ID to all managed devices via the Windows Registry. End users cannot override IT policy.
• Silent install script (Invoke-WardenProvision.ps1) included.
• MSP multi-tenant dashboard — per-tenant usage, block statistics, and monthly compliance reports.
• Monthly PDF compliance reports with white-label branding (your logo, your company name).

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SUPPORTED AI PLATFORMS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✔ ChatGPT (chatgpt.com)
✔ Claude (claude.ai)
✔ Google Gemini (gemini.google.com)
✔ Microsoft Copilot (copilot.microsoft.com)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
PRIVACY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• No data is sent to Shadow Warden AI's servers. Ever.
• The extension contains no third-party analytics, tracking, or advertising code.
• All analysis runs on your organisation's own infrastructure.
• Full privacy policy: https://shadowwarden.ai/privacy

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REQUIREMENTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

• A running Shadow Warden AI gateway (Docker image available at hub.docker.com/r/shadowwarden/warden)
• Chrome 120+ or Microsoft Edge 120+
• For enterprise deployment: Windows 10/11 with Group Policy or Microsoft Intune

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OPEN SOURCE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

The gateway component is available on GitHub. The extension source is included in the same repository for full auditability.
```

---

## Permission Justifications

*(Required for Manifest V3 extensions with non-trivial permissions. Enter verbatim into each field in the "Permissions" tab of the Developer Dashboard.)*

### `storage`
```
Required to store the gateway URL, API key, and tenant identifier configured by the IT administrator, and to maintain session statistics (blocks today, requests today) locally on the device.
```

### `scripting`
```
Required to inject the fetch-interceptor content script into supported AI platform pages (ChatGPT, Claude, Gemini, Copilot) at document_start, before any AI request can be initiated.
```

### `notifications`
```
Required to show a desktop notification when a high-risk prompt is blocked, so the user understands why their AI request did not proceed.
```

### Host permission — `https://chatgpt.com/*`, `https://chat.openai.com/*`
```
Required to intercept outbound fetch requests to ChatGPT's conversation API endpoint (backend-api/conversation) before they are transmitted, so the prompt can be evaluated against the organisation's data protection policy.
```

### Host permission — `https://claude.ai/*`
```
Required to intercept outbound fetch requests to Claude's completion API endpoint before they are transmitted, so the prompt can be evaluated against the organisation's data protection policy.
```

### Host permission — `https://gemini.google.com/*`
```
Required to intercept outbound fetch requests to Gemini's StreamGenerate API endpoint before they are transmitted, so the prompt can be evaluated against the organisation's data protection policy.
```

### Host permission — `https://copilot.microsoft.com/*`
```
Required to intercept outbound fetch requests to Microsoft Copilot's chat API endpoint before they are transmitted, so the prompt can be evaluated against the organisation's data protection policy.
```

---

## Single Purpose Statement

*(Required for extensions using remote host access. Enter verbatim.)*

```
Shadow Warden AI has a single purpose: to intercept outbound AI prompts on supported platforms (ChatGPT, Claude, Gemini, Microsoft Copilot) and evaluate them against the organisation's data-loss prevention policy before transmission. No other browser activity is monitored, modified, or logged.
```

---

## Privacy Practices (Data Use Disclosure)

*(Chrome Web Store "Privacy practices" tab — tick the relevant boxes.)*

| Question | Answer |
|----------|--------|
| Does the extension handle personally identifiable information? | **No** — the extension reads prompt text only to forward it to the local gateway; it does not store, transmit externally, or retain any personal data. |
| Does the extension use remote code? | **No** — all code is bundled in the extension package. No scripts are fetched at runtime. |
| Does the extension use web accessible resources beyond icons? | **No** — `web_accessible_resources` includes only icons and the popup UI, both bundled in the package. |

**Privacy Policy URL to enter in the dashboard:**
```
https://shadowwarden.ai/privacy
```

*(Host this file at the URL above before submitting. The PRIVACY_POLICY.md in this repo is the authoritative source.)*

---

## Review Notes for Google

*(Enter in the "Notes to reviewer" field during submission. Max 1 000 chars.)*

```
Shadow Warden AI is an enterprise AI data-loss prevention tool for IT administrators and Managed Service Providers (MSPs).

The extension overrides window.fetch (content_scripts world: "MAIN") exclusively to inspect the request body of outbound AI API calls on five supported AI platforms. This technique is required because Manifest V3 does not support declarativeNetRequest for modifying POST request bodies before they are sent.

The prompt text is forwarded only to the organisation's own local gateway (default: http://localhost:8001, configurable via Group Policy). No data is sent to Shadow Warden AI's servers. The extension fails open if the gateway is unreachable.

All source code is available for review at: https://github.com/shadowwarden-ai/warden

Test credentials for a live demo environment:
  Gateway: https://demo.shadowwarden.ai
  API Key: sw_demo_reviewer_2026
  Tenant ID: chrome_review
```

---

## Screenshots (Required — 1280×800 or 640×400)

Prepare the following 5 screenshots before submission:

| # | Scene | Key elements to show |
|---|-------|---------------------|
| 1 | RED block overlay on ChatGPT | Full-screen block modal with risk level badge, reason, dismiss button |
| 2 | YELLOW advisory overlay | Two-button overlay: "Send to Local AI" + "Cancel", prompt preview |
| 3 | Extension popup (popup.html) | Status: enabled, blocks today counter, gateway connected |
| 4 | MSP dashboard | Per-tenant table with plan, blocks, monthly report download |
| 5 | Monthly PDF compliance report | Cover page with logo, KPI grid, threat intelligence table |

**Promotional tile (440×280):**
Dark background, shield icon, tagline: "Stop sensitive data from reaching cloud AI — before it's too late."

---

## Category & Visibility

| Field | Value |
|-------|-------|
| Category | Productivity |
| Visibility | Public |
| Distribution | All regions (or limit to US/EU for initial launch) |
| Pricing | Free (gateway requires a paid subscription) |
