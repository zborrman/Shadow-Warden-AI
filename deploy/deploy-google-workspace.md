# Shadow Warden AI — Google Workspace Deployment Guide

Deploy the extension silently to all employees via Google Admin Console.
No employee action needed. Extension pre-configured with tenant credentials.

## Prerequisites

- Google Workspace Business or Enterprise account
- Shadow Warden AI published to Chrome Web Store (private listing OK)
- Extension ID from the Web Store developer dashboard

---

## Step 1 — Publish to Chrome Web Store (Private)

1. Go to [Chrome Web Store Developer Dashboard](https://chrome.google.com/webstore/devconsole)
2. Click **Add new item**
3. Upload `browser-extension/` as a ZIP
4. Set **Visibility** → **Private (for your organization)**
5. Note the **Extension ID** (32-character string)

---

## Step 2 — Force-install via Google Admin Console

1. Open [Google Admin Console](https://admin.google.com)
2. Navigate to: **Devices** → **Chrome** → **Apps & Extensions**
3. Select the target **Organizational Unit** (e.g., "All Users" or specific department)
4. Click **+** → **Add from Chrome Web Store**
5. Paste the Extension ID → **Select**
6. Set **Installation policy** → **Force install**
7. Click **Save**

Chrome will install the extension on all managed devices within ~15 minutes.

---

## Step 3 — Pre-configure via Managed Storage Policy

This is the key step — employees never see a setup screen.

1. In Google Admin Console → **Devices** → **Chrome** → **Apps & Extensions**
2. Click on the Shadow Warden AI extension
3. Scroll to **Managed configuration** (or **Policy for extensions**)
4. Click **Edit configuration**
5. Enter the JSON below, replacing placeholder values:

```json
{
  "gatewayUrl":    "https://your-hetzner-server.com",
  "apiKey":        "64-character-api-key-from-POST-/onboard",
  "tenantId":      "client-company-slug",
  "ollamaUrl":     "http://localhost:3000",
  "enabled":       true,
  "notifyOnBlock": true,
  "minRiskNotify": "high"
}
```

6. Click **Save**

The extension reads these values from `chrome.storage.managed` on startup.
Employees cannot change or view the API key.

---

## Step 4 — Per-department configuration (multi-tenant MSP)

For MSPs managing multiple clients, create separate Organizational Units:

```
All Users
├── Acme Dental          → apiKey: key-acme, tenantId: acme-dental
├── Blue Sky Legal       → apiKey: key-blue, tenantId: blue-sky-legal
└── Riverside Realty     → apiKey: key-river, tenantId: riverside-realty
```

Each department gets its own policy with different `apiKey` and `tenantId`.
All their block events appear in the MSP dashboard under the correct tenant.

---

## Step 5 — Verify deployment

Run this on any managed Chrome device after 15 minutes:

```javascript
// Open DevTools (F12) on any page, paste in Console:
chrome.storage.managed.get(null, console.log)

// Expected output:
// { gatewayUrl: "https://...", tenantId: "...", enabled: true, ... }
```

Or check the popup — it should show "Protected" status immediately with no setup needed.

---

## Windows GPO Alternative (non-Google-Workspace)

For businesses not using Google Workspace, use the PowerShell script:

```powershell
# Run as Administrator on each machine (or deploy via Intune):
.\deploy-chrome-gpo.ps1 `
    -ExtensionId "abcdefghijklmnopabcdefghijklmnop" `
    -GatewayUrl  "https://your-hetzner.com" `
    -ApiKey      "your-64-char-key" `
    -TenantId    "acme-dental"

# Dry run first to preview changes:
.\deploy-chrome-gpo.ps1 ... -DryRun
```

Registry keys written:
- `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist` — force install
- `HKLM\SOFTWARE\Policies\Google\Chrome\ExtensionSettings` — lock (user cannot disable)
- `HKLM\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\{ID}\policy` — pre-config

---

## Intune (Microsoft MDM) deployment

1. Create a **PowerShell script** in Intune
2. Upload `deploy-chrome-gpo.ps1` with parameters
3. Assign to Device group
4. Set **Run as**: System account

Or use Intune's native Chrome extension management:
- **Devices** → **Configuration profiles** → **Create profile**
- Platform: **Windows 10 and later** → Profile: **Administrative Templates**
- Search "Force-install" → Add Extension ID + config JSON

---

## Testing the deployment (MSP checklist)

```bash
# 1. Verify extension installed (check chrome://extensions/ on client machine)
# 2. Open ChatGPT — type a fake SSN: "123-45-6789"
#    → Should see RED block overlay within 1-2 seconds
# 3. Type "our customer list" → Should see YELLOW advisory + Ollama button
# 4. Check Telegram — should receive block alert notification
# 5. Check MSP dashboard /billing/{tenant_id} — should show 1-2 blocked requests
```
