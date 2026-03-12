<#
.SYNOPSIS
    Shadow Warden AI — Zero-Touch Endpoint Provisioning

.DESCRIPTION
    Calls POST /onboard to generate a tenant API key, then writes Chrome and Edge
    Group Policy registry keys so the browser extension installs and configures
    itself automatically on next launch.

    The MSP master key is used ONLY to call /onboard and is NEVER written to the
    endpoint registry.  The per-tenant API key (returned by /onboard) is the only
    credential stored locally.

.PARAMETER GatewayUrl
    Base URL of the Shadow Warden gateway.
    Example: https://ai.acme-msp.com

.PARAMETER MspApiKey
    MSP-level API key (X-API-Key).  Used to authenticate /onboard.
    Typically passed from RMM as a secure environment variable — never hard-coded.

.PARAMETER CompanyName
    Human-readable company name.  Used as the tenant display name.
    Example: "Acme Dental Clinic"

.PARAMETER ContactEmail
    Contact e-mail stored on the server for this tenant.

.PARAMETER Plan
    Billing plan: starter | professional | enterprise  (default: starter)

.PARAMETER ExtensionId
    Chrome Web Store extension ID.
    Default: the published Shadow Warden extension ID.

.PARAMETER OllamaUrl
    Local Ollama URL for this endpoint (default: http://localhost:11434).

.PARAMETER DryRun
    Print what would be done without writing any registry keys or calling /onboard.

.PARAMETER Force
    Re-provision even if registry keys already exist (overwrites).

.EXAMPLE
    # Typical RMM deployment — key comes from RMM secret store
    .\Invoke-WardenProvision.ps1 `
        -GatewayUrl  "https://ai.acme-msp.com" `
        -MspApiKey   $env:MSP_WARDEN_KEY `
        -CompanyName "Riverside Dental" `
        -ContactEmail "it@riverside-dental.com"

.EXAMPLE
    # Dry run — see what would happen
    .\Invoke-WardenProvision.ps1 -GatewayUrl https://ai.acme-msp.com `
        -MspApiKey test -CompanyName "Test Clinic" -DryRun

.NOTES
    Exit codes:
        0 — Success (provisioned)
        1 — Error (network failure, auth error, etc.)
        2 — Already provisioned (use -Force to re-provision)
    Output: JSON to stdout for RMM log capture
    Requires: PowerShell 5.1+ or PowerShell 7+, admin rights for HKLM writes
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string] $GatewayUrl,
    [Parameter(Mandatory)][string] $MspApiKey,
    [Parameter(Mandatory)][string] $CompanyName,
    [Parameter(Mandatory)][string] $ContactEmail,
    [string] $Plan          = "starter",
    [string] $ExtensionId   = "WARDEN_EXTENSION_ID_PLACEHOLDER",
    [string] $OllamaUrl     = "http://localhost:11434",
    [switch] $DryRun,
    [switch] $Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Constants ─────────────────────────────────────────────────────────────────

$CHROME_FORCELIST_PATH = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
$EDGE_FORCELIST_PATH   = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
$CHROME_POLICY_PATH    = "HKLM:\SOFTWARE\Policies\Google\Chrome\3rdparty\extensions\$ExtensionId\policy"
$EDGE_POLICY_PATH      = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\3rdparty\extensions\$ExtensionId\policy"
$CRX_UPDATE_URL        = "https://clients2.google.com/service/update2/crx"
$PROVISION_MARKER      = "HKLM:\SOFTWARE\ShadowWarden\Provisioning"

# ── Helpers ───────────────────────────────────────────────────────────────────

function Write-Result([hashtable]$data) {
    $data | ConvertTo-Json -Compress | Write-Output
}

function Ensure-RegistryPath([string]$path) {
    if (-not (Test-Path $path)) {
        if (-not $DryRun) { New-Item -Path $path -Force | Out-Null }
        Write-Verbose "Created registry path: $path"
    }
}

function Set-RegistryValue([string]$path, [string]$name, $value, [string]$type = "String") {
    if ($DryRun) {
        Write-Verbose "[DryRun] Set $path\$name = $value ($type)"
        return
    }
    Ensure-RegistryPath $path
    Set-ItemProperty -Path $path -Name $name -Value $value -Type $type -Force
}

# ── Check already provisioned ─────────────────────────────────────────────────

if (-not $Force -and (Test-Path $PROVISION_MARKER)) {
    $marker = Get-ItemProperty -Path $PROVISION_MARKER -ErrorAction SilentlyContinue
    if ($marker -and $marker.TenantId) {
        Write-Result @{
            status    = "already_provisioned"
            tenant_id = $marker.TenantId
            company   = $marker.CompanyName
            message   = "Use -Force to re-provision."
        }
        exit 2
    }
}

# ── Step 1: Call POST /onboard ─────────────────────────────────────────────────

$gatewayBase = $GatewayUrl.TrimEnd("/")
$onboardUrl  = "$gatewayBase/onboard"

Write-Verbose "Calling $onboardUrl ..."

$body = @{
    company_name  = $CompanyName
    contact_email = $ContactEmail
    plan          = $Plan
} | ConvertTo-Json

if ($DryRun) {
    Write-Verbose "[DryRun] Would POST to $onboardUrl with body: $body"
    # Simulate a response for dry-run output
    $tenantId = "dryrun-$(([System.Guid]::NewGuid().ToString('N'))[0..7] -join '')"
    $apiKey   = "sw-dryrun-key-000000"
} else {
    try {
        $resp = Invoke-RestMethod `
            -Uri         $onboardUrl `
            -Method      POST `
            -ContentType "application/json" `
            -Body        $body `
            -Headers     @{ "X-API-Key" = $MspApiKey } `
            -TimeoutSec  30

        $tenantId = $resp.tenant_id
        $apiKey   = $resp.api_key

        if (-not $tenantId -or -not $apiKey) {
            Write-Result @{
                status  = "error"
                message = "Onboard response missing tenant_id or api_key."
                raw     = ($resp | ConvertTo-Json -Compress)
            }
            exit 1
        }
    }
    catch {
        Write-Result @{
            status  = "error"
            message = "POST /onboard failed: $($_.Exception.Message)"
            url     = $onboardUrl
        }
        exit 1
    }
}

Write-Verbose "Tenant provisioned: $tenantId"

# ── Step 2: Write Chrome force-install + managed storage registry keys ─────────

$forcelistValue = "${ExtensionId};${CRX_UPDATE_URL}"

# Force-install for Chrome
Ensure-RegistryPath $CHROME_FORCELIST_PATH
Set-RegistryValue $CHROME_FORCELIST_PATH "1" $forcelistValue

# Force-install for Edge
Ensure-RegistryPath $EDGE_FORCELIST_PATH
Set-RegistryValue $EDGE_FORCELIST_PATH "1" $forcelistValue

# Managed storage policy for Chrome (chrome.storage.managed)
Set-RegistryValue $CHROME_POLICY_PATH "gatewayUrl"  $gatewayBase
Set-RegistryValue $CHROME_POLICY_PATH "apiKey"      $apiKey
Set-RegistryValue $CHROME_POLICY_PATH "tenantId"    $tenantId
Set-RegistryValue $CHROME_POLICY_PATH "ollamaUrl"   $OllamaUrl
Set-RegistryValue $CHROME_POLICY_PATH "enabled"     "true"
Set-RegistryValue $CHROME_POLICY_PATH "managed"     "true"   # signals extension to lock UI

# Managed storage policy for Edge
Set-RegistryValue $EDGE_POLICY_PATH "gatewayUrl"  $gatewayBase
Set-RegistryValue $EDGE_POLICY_PATH "apiKey"      $apiKey
Set-RegistryValue $EDGE_POLICY_PATH "tenantId"    $tenantId
Set-RegistryValue $EDGE_POLICY_PATH "ollamaUrl"   $OllamaUrl
Set-RegistryValue $EDGE_POLICY_PATH "enabled"     "true"
Set-RegistryValue $EDGE_POLICY_PATH "managed"     "true"

# ── Step 3: Write provision marker (so re-runs are idempotent) ─────────────────

if (-not $DryRun) {
    Ensure-RegistryPath $PROVISION_MARKER
    Set-ItemProperty -Path $PROVISION_MARKER -Name "TenantId"    -Value $tenantId      -Type String -Force
    Set-ItemProperty -Path $PROVISION_MARKER -Name "CompanyName" -Value $CompanyName   -Type String -Force
    Set-ItemProperty -Path $PROVISION_MARKER -Name "GatewayUrl"  -Value $gatewayBase   -Type String -Force
    Set-ItemProperty -Path $PROVISION_MARKER -Name "ProvisionedAt" -Value (Get-Date -Format "o") -Type String -Force
}

# ── Done ──────────────────────────────────────────────────────────────────────

Write-Result @{
    status      = if ($DryRun) { "dry_run" } else { "ok" }
    tenant_id   = $tenantId
    company     = $CompanyName
    gateway_url = $gatewayBase
    message     = if ($DryRun) {
        "Dry run complete — no registry keys written."
    } else {
        "Extension will auto-install on next Chrome/Edge launch."
    }
}

exit 0
