# Shadow Warden AI — Browser Extension

Intercepts prompts sent to ChatGPT, Claude.ai, Gemini, and Copilot
before they leave the browser. Blocks PII, financial data, and confidential
content using your Shadow Warden gateway on Hetzner.

## Installation (Chrome / Edge — Developer Mode)

1. Open Chrome and go to: `chrome://extensions/`
2. Enable **Developer mode** (toggle, top-right)
3. Click **Load unpacked**
4. Select this `browser-extension/` folder
5. The Shadow Warden shield icon appears in the toolbar

## First-time Setup

1. Click the shield icon in the toolbar
2. Enter your **Shadow Warden URL** (e.g. `https://your-hetzner-server.com`)
3. Enter your **API Key** from your administrator (issued via `POST /onboard`)
4. Enter your **Tenant ID** (e.g. `acme-dental`)
5. Click **Test Connection** → should show ✅
6. Click **Save & Connect**

## How it works

```
[Employee types prompt in ChatGPT]
         ↓
  content.js intercepts window.fetch()
         ↓
  POST /filter → Shadow Warden on Hetzner
         ↓
  secret_redactor + semantic_guard + data_policy
         ↓
  allowed=true  → request passes through unchanged
  allowed=false → overlay shown, request cancelled, Telegram alert sent
```

## For MSP Admins — deploying to all employees

### Chrome Enterprise / Google Workspace (recommended)

1. Upload the extension to Chrome Web Store (private listing)
2. In Google Admin Console → Devices → Chrome → Apps & Extensions
3. Force-install for your organization
4. Pre-configure via **managed storage** (no employee setup needed):

```json
{
  "gatewayUrl": { "Value": "https://your-hetzner.com" },
  "apiKey":     { "Value": "tenant-api-key-here" },
  "tenantId":   { "Value": "client-company-slug" }
}
```

### Microsoft Intune (Edge)

Deploy via Intune as a managed browser extension with the same JSON policy.

## Environment variables (Shadow Warden gateway)

```env
# Allow extension origins — add to CORS_ORIGINS if overriding the default
CORS_ORIGINS=https://chatgpt.com,https://claude.ai,https://gemini.google.com,https://copilot.microsoft.com

# Telegram alerts for block events
TELEGRAM_BOT_TOKEN=your-bot-token
TELEGRAM_CHAT_ID=-your-chat-id
```

## Supported AI sites

| Site | Endpoint intercepted |
|------|---------------------|
| ChatGPT (chatgpt.com) | `/backend-api/conversation` |
| Claude.ai | `/api/.../completion` |
| Gemini | `StreamGenerate` |
| Microsoft Copilot | `/c/api/chat` |

## What gets blocked

Determined by Shadow Warden's data policy engine:

- 🔴 **RED** (always blocked): Financial records, NDA/legal docs, HR data, medical/HIPAA
- 🟡 **YELLOW** (cloud AI blocked): Customer lists, internal memos, strategy docs
- 🚫 **PII**: Credit cards, SSN, IBAN, email, phone numbers, crypto wallets
- 🚫 **Secrets**: API keys, passwords, tokens

## Testing

```bash
# Test that CORS is configured correctly on your gateway
curl -i -X OPTIONS https://your-gateway.com/filter \
  -H "Origin: https://chatgpt.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type,X-API-Key"
# Expect: Access-Control-Allow-Origin: https://chatgpt.com

# Test filter endpoint directly
curl -X POST https://your-gateway.com/filter \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{"content": "My SSN is 123-45-6789 please analyze this"}'
# Expect: {"allowed": false, "risk_level": "high", ...}
```
