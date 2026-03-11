<#
.SYNOPSIS
    Silent deployment of Shadow Warden AI browser extension via Windows Registry (GPO).

.DESCRIPTION
    Deploys the Shadow Warden AI Chrome extension to all users on this machine
    without any user interaction. Uses Windows Registry policies that Chrome reads
    on startup.

    Can be run:
      1. Directly on a target machine (admin rights required)
      2. Via Intune PowerShell script deployment
      3. Via Group Policy > Computer Configuration > Scripts > Startup

.PARAMETER ExtensionId
    Chrome Web Store extension ID (get this after publishing).
    For dev/testing use "load_unpacked" method instead.

.PARAMETER GatewayUrl
    URL of the Shadow Warden AI gateway (your Hetzner server).

.PARAMETER ApiKey
    Tenant API key issued by your MSP.

.PARAMETER TenantId
    Company tenant identifier (e.g. "acme-dental").

.PARAMETER OllamaUrl
    Local AI URL for YELLOW zone redirect (default: http://localhost:3000).

.EXAMPLE
    .\deploy-chrome-gpo.ps1 `
        -ExtensionId "abcdefghijklmnopabcdefghijklmnop" `
        -GatewayUrl  "https://ai.acmedental.com" `
        -ApiKey      "your-64-char-api-key" `
        -TenantId    "acme-dental"

.NOTES
    Requires Chrome 93+ (Manifest V3 support).
    Tested on Windows 10/11.
    Run as Administrator.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]  [string] $ExtensionId,
    [Parameter(Mandatory=$true)]  [string] $GatewayUrl,
    [Parameter(Mandatory=$true)]  [string] $ApiKey,
    [Parameter(Mandatory=$true)]  [string] $TenantId,
    [Parameter(Mandatory=$false)] [string] $OllamaUrl = "http://localhost:3000",
    [Parameter(Mandatory=$false)] [switch] $DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-Step { param([string]$msg) Write-Host "  [WARDEN] $msg" -ForegroundColor Cyan }
function Write-OK    { param([string]$msg) Write-Host "  [OK]     $msg" -ForegroundColor Green }
function Write-Warn  { param([string]$msg) Write-Host "  [WARN]   $msg" -ForegroundColor Yellow }

Write-Host ""
Write-Host "Shadow Warden AI — Silent Deploy Script" -ForegroundColor White
Write-Host "========================================" -ForegroundColor DarkGray
Write-Host "  Extension : $ExtensionId"
Write-Host "  Gateway   : $GatewayUrl"
Write-Host "  Tenant    : $TenantId"
Write-Host "  DryRun    : $($DryRun.IsPresent)"
Write-Host ""

# ── Validate inputs ────────────────────────────────────────────────────────────

if ($ExtensionId.Length -ne 32) {
    Write-Warn "ExtensionId should be 32 characters. Got: $($ExtensionId.Length)"
    Write-Warn "This is OK for development/sideloading."
}

if (!$GatewayUrl.StartsWith("http")) {
    throw "GatewayUrl must start with http:// or https://"
}

if ($ApiKey.Length -lt 32) {
    throw "ApiKey too short (expected 64-char hex from /onboard)"
}

# ── Registry paths ─────────────────────────────────────────────────────────────

$ChromePolicyBase   = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ExtensionInstall   = "$ChromePolicyBase\ExtensionInstallForcelist"
$ExtensionSettings  = "$ChromePolicyBase\ExtensionSettings"
$ManagedStorage     = "$ChromePolicyBase\3rdparty\extensions\$ExtensionId\policy"

# Chrome Web Store URL format for force-install
$StoreUrl = "https://clients2.google.com/service/update2/crx"

# ── Policy JSON for extension settings ─────────────────────────────────────────

$managedConfig = [ordered]@{
    gatewayUrl    = $GatewayUrl
    apiKey        = $ApiKey
    tenantId      = $TenantId
    ollamaUrl     = $OllamaUrl
    enabled       = $true
    notifyOnBlock = $true
    minRiskNotify = "high"
}

$managedConfigJson = $managedConfig | ConvertTo-Json -Compress

# ── Apply registry entries ─────────────────────────────────────────────────────

function Set-RegValue {
    param([string]$Path, [string]$Name, $Value, [string]$Type = "String")

    if ($DryRun) {
        Write-Step "DRY-RUN: Set-Item '$Path\$Name' = '$Value'"
        return
    }

    if (!(Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type
}

# 1. Force-install the extension from Chrome Web Store
Write-Step "Configuring force-install from Chrome Web Store..."
Set-RegValue -Path $ExtensionInstall -Name "1" -Value "${ExtensionId};${StoreUrl}"
Write-OK "Extension ${ExtensionId} added to force-install list."

# 2. Prevent user from disabling or removing the extension
Write-Step "Locking extension settings (user cannot disable)..."
$extensionPolicy = @{
    installation_mode = "force_installed"
    update_url        = $StoreUrl
} | ConvertTo-Json -Compress

Set-RegValue -Path $ExtensionSettings -Name $ExtensionId -Value $extensionPolicy
Write-OK "Extension policy locked."

# 3. Write managed storage (pre-configured gateway + API key)
Write-Step "Writing managed storage config..."
Set-RegValue -Path $ManagedStorage -Name "gatewayUrl"    -Value $GatewayUrl
Set-RegValue -Path $ManagedStorage -Name "apiKey"        -Value $ApiKey
Set-RegValue -Path $ManagedStorage -Name "tenantId"      -Value $TenantId
Set-RegValue -Path $ManagedStorage -Name "ollamaUrl"     -Value $OllamaUrl
Set-RegValue -Path $ManagedStorage -Name "enabled"       -Value 1 -Type "DWord"
Set-RegValue -Path $ManagedStorage -Name "notifyOnBlock" -Value 1 -Type "DWord"
Set-RegValue -Path $ManagedStorage -Name "minRiskNotify" -Value "high"
Write-OK "Managed storage written to registry."

# ── Summary ────────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:"
Write-Host "  1. Chrome will auto-install the extension on next browser restart."
Write-Host "  2. The extension will be pre-configured with tenant credentials."
Write-Host "  3. Users cannot disable or uninstall the extension."
Write-Host ""
Write-Host "To verify on this machine:"
Write-Host "  Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist'"
Write-Host ""
if ($DryRun) {
    Write-Warn "DRY-RUN mode — no registry changes were made."
}
