# Shadow Warden AI — Privacy Policy

**Effective date:** 2026-03-13
**Last reviewed:** 2026-03-13
**Product:** Shadow Warden AI Browser Extension (Chrome / Edge)
**Developer:** Shadow Warden AI
**Contact:** privacy@shadowwarden.ai

---

## 1. Overview

Shadow Warden AI is an AI data-loss prevention (DLP) extension. Its **single purpose** is to intercept outbound AI prompts typed in your browser and evaluate them against your organisation's data protection policy *before* they are transmitted to a cloud AI service.

All analysis is performed by a **local gateway** operated by your organisation (or on your own device). **No prompt content is ever transmitted to Shadow Warden AI's servers or any third party.**

---

## 2. Data We Collect and Process

### 2a. What the extension reads

When you type a message and press Send on a supported AI platform (ChatGPT, Claude, Gemini, Microsoft Copilot), the extension:

1. **Reads the outgoing prompt text** from the page's JavaScript context, before the request leaves your browser.
2. **Sends that text** to the Shadow Warden **local gateway** — a server your organisation controls, running at the URL configured by your IT administrator (default: `http://localhost:8001`). The text is transmitted only over this local network connection.

The extension **never** transmits prompt content to any external server operated by Shadow Warden AI.

### 2b. What the local gateway logs

The local gateway is software run and controlled entirely by your organisation. It records only **request metadata** — never the content of your prompts:

| Field | Description |
|-------|-------------|
| `ts` | UTC timestamp |
| `tenant_id` | Organisational identifier configured by IT |
| `risk_level` | Computed risk classification (low / medium / high / block) |
| `allowed` | Whether the request was permitted |
| `payload_len` | Number of characters in the prompt (integer only) |
| `payload_tokens` | Estimated token count |
| `flags` | Category labels (e.g. `pii_detected`, `secret_detected`) |
| `entities_detected` | Entity *type* labels only (e.g. `EMAIL`, `PHONE`) — never the actual values |
| `elapsed_ms` | Processing latency |

**Prompt content is never written to disk.** This is a hard-coded constraint in the gateway's GDPR compliance design.

### 2c. Extension storage

The extension stores the following in `chrome.storage.sync` and `chrome.storage.local`:

| Key | Purpose | Scope |
|-----|---------|-------|
| `gatewayUrl` | URL of your local Warden gateway | Set by IT admin via Group Policy or user settings |
| `apiKey` | Authentication token for the local gateway | Set by IT admin |
| `tenantId` | Organisational tenant identifier | Set by IT admin |
| `enabled` | Whether filtering is active | User-configurable |
| `notifyOnBlock` | Show desktop notification when a request is blocked | User-configurable |
| `minRiskNotify` | Minimum risk level for notifications | User-configurable |
| `blocksToday` / `requestsToday` | Session statistics counter | Local device only, reset daily |

**None of this data is transmitted to Shadow Warden AI or any third party.**

---

## 3. Data We Do NOT Collect

- The text of any AI prompt or conversation
- Browser history or visited URLs (beyond detecting AI platform domains)
- Personally identifiable information from web pages
- Cookies, authentication tokens, or session data
- Financial information, health records, or any sensitive personal data
- Data from websites other than the five supported AI platforms

---

## 4. Host Permissions — Justification

The extension requests access to the following domains:

| Domain | Reason |
|--------|--------|
| `chatgpt.com`, `chat.openai.com` | Intercept outbound prompts sent to ChatGPT |
| `claude.ai` | Intercept outbound prompts sent to Claude |
| `gemini.google.com` | Intercept outbound prompts sent to Gemini |
| `copilot.microsoft.com` | Intercept outbound prompts sent to Microsoft Copilot |

Access is limited strictly to intercepting the single outbound API request that carries the prompt. The extension does not read page content, cookies, or any other resources on these domains.

**The extension does not function on any other website.**

---

## 5. How Prompt Interception Works (Technical)

The extension injects a content script that overrides `window.fetch` in the page's JavaScript context. When a fetch request matches a known AI API endpoint:

1. The prompt text is extracted from the request body.
2. The text is forwarded to your local Warden gateway via a separate fetch call.
3. The gateway returns a decision: `allowed`, `blocked`, or an advisory.
4. Based on the decision, the original request is either passed through, blocked, or the user is shown an advisory overlay.

If the local gateway is **unreachable** (network error, timeout), the extension **fails open** — the original request is sent to the AI service without modification. The extension will never silently break your workflow.

---

## 6. Permissions Used

| Permission | Why it is needed |
|------------|-----------------|
| `storage` | Store gateway URL, API key, and session statistics locally |
| `scripting` | Inject the fetch-interceptor content script at page load |
| `notifications` | Show a desktop notification when a high-risk request is blocked |
| Host permissions (5 AI domains) | Intercept outbound prompts on supported AI platforms |

---

## 7. Enterprise / Managed Deployment

Organisations deploying Shadow Warden AI via Windows Group Policy (GPO) or Microsoft Intune provide the gateway URL, API key, and tenant ID through `chrome.storage.managed`. These values are configured exclusively by IT administrators and cannot be modified by end users.

No managed configuration data is transmitted to Shadow Warden AI servers.

---

## 8. Third-Party Data Sharing

Shadow Warden AI does **not** share any data with third parties. The extension does not contain:

- Analytics libraries (Google Analytics, Mixpanel, etc.)
- Advertising or tracking SDKs
- Crash-reporting services that transmit data externally
- Any remote code loading

---

## 9. Data Retention

- **Extension storage** (`chrome.storage`): Retained on-device until the extension is uninstalled or the user clears extension data. Session statistics (`blocksToday`, `requestsToday`) are reset daily.
- **Local gateway logs**: Controlled entirely by your organisation. The gateway provides GDPR-compliant purge endpoints (`POST /gdpr/purge`) to delete logs by date range or request ID.

---

## 10. Your Rights (GDPR / CCPA)

Because prompt content is never stored by Shadow Warden AI, there is no personal data held by us to access, correct, or delete.

For data held by your **local gateway** (metadata logs), contact your IT administrator. The gateway's `/gdpr/export` and `/gdpr/purge` endpoints give administrators full control over log retention.

For any privacy questions directed to Shadow Warden AI as the extension developer, contact **privacy@shadowwarden.ai**.

---

## 11. Children's Privacy

This product is designed for enterprise and business use. It is not directed at children under 13 (US) or 16 (EU/GDPR). We do not knowingly collect data from minors.

---

## 12. Changes to This Policy

Material changes will be communicated by updating the version number and date at the top of this document. Continued use of the extension following a policy update constitutes acceptance of the revised terms.

---

## 13. Contact

**Shadow Warden AI — Privacy Team**
Email: privacy@shadowwarden.ai
Subject line: "Browser Extension Privacy Inquiry"
