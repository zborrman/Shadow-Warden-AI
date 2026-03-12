<#
.SYNOPSIS
    Shadow Warden AI — Mass Rollout via CSV

.DESCRIPTION
    Reads a CSV of endpoints and calls Invoke-WardenProvision.ps1 on each one
    via Invoke-Command (WinRM) or PsExec, depending on the RMM environment.

    Designed to be called from ConnectWise Automate, NinjaRMM, Datto, or Kaseya
    with a single job targeting an "All Clients" device filter.

    The MSP key is passed once at the top level and is NOT stored in the CSV.

.PARAMETER CsvPath
    Path to endpoints CSV.  Required columns: Hostname, CompanyName, ContactEmail
    Optional: Plan, OllamaUrl

.PARAMETER GatewayUrl
    Shadow Warden gateway base URL.

.PARAMETER MspApiKey
    MSP master API key.  Pass from RMM secret store — never hard-code.

.PARAMETER MaxConcurrent
    Max simultaneous provisioning jobs (default: 10).

.PARAMETER DryRun
    Pass -DryRun to all sub-jobs — no actual changes made.

.PARAMETER ResultCsvPath
    Where to write the per-host result CSV (default: rollout_results_<timestamp>.csv).

.EXAMPLE
    .\Invoke-MassRollout.ps1 `
        -CsvPath      .\endpoints.csv `
        -GatewayUrl   "https://ai.acme-msp.com" `
        -MspApiKey    $env:MSP_WARDEN_KEY `
        -ResultCsvPath .\results\$(Get-Date -Format yyyyMMdd_HHmm)_rollout.csv
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string] $CsvPath,
    [Parameter(Mandatory)][string] $GatewayUrl,
    [Parameter(Mandatory)][string] $MspApiKey,
    [int]    $MaxConcurrent  = 10,
    [switch] $DryRun,
    [string] $ResultCsvPath  = "rollout_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$scriptRoot = $PSScriptRoot
$provisionScript = Join-Path (Split-Path $scriptRoot) "Invoke-WardenProvision.ps1"

if (-not (Test-Path $provisionScript)) {
    Write-Error "Invoke-WardenProvision.ps1 not found at: $provisionScript"
    exit 1
}

# ── Load CSV ──────────────────────────────────────────────────────────────────

$endpoints = Import-Csv -Path $CsvPath
$total     = $endpoints.Count
Write-Host "[MassRollout] Loaded $total endpoint(s) from $CsvPath" -ForegroundColor Cyan

if ($DryRun) {
    Write-Host "[MassRollout] DRY RUN mode — no changes will be made." -ForegroundColor Yellow
}

# ── Per-host job ──────────────────────────────────────────────────────────────

$jobBlock = {
    param($ep, $GatewayUrl, $MspApiKey, $ProvisionScript, $IsDryRun)

    $hostname     = $ep.Hostname
    $companyName  = $ep.CompanyName
    $contactEmail = $ep.ContactEmail
    $plan         = if ($ep.Plan)      { $ep.Plan }      else { "starter" }
    $ollamaUrl    = if ($ep.OllamaUrl) { $ep.OllamaUrl } else { "http://localhost:11434" }

    $params = @{
        GatewayUrl    = $GatewayUrl
        MspApiKey     = $MspApiKey
        CompanyName   = $companyName
        ContactEmail  = $contactEmail
        Plan          = $plan
        OllamaUrl     = $ollamaUrl
        ErrorAction   = "Stop"
    }
    if ($IsDryRun) { $params["DryRun"] = $true }

    try {
        # Run locally if hostname matches this machine, else WinRM
        if ($hostname -eq $env:COMPUTERNAME -or $hostname -eq "localhost") {
            $raw = & $ProvisionScript @params 2>&1
        } else {
            $raw = Invoke-Command -ComputerName $hostname -ScriptBlock {
                param($s, $p) & $s @p
            } -ArgumentList $ProvisionScript, $params -ErrorAction Stop 2>&1
        }

        $result = $raw | Where-Object { $_ -match '^\{' } | Select-Object -Last 1
        if ($result) {
            $parsed = $result | ConvertFrom-Json
            return [pscustomobject]@{
                Hostname  = $hostname
                Company   = $companyName
                Status    = $parsed.status
                TenantId  = $parsed.tenant_id
                Message   = $parsed.message
                Error     = ""
            }
        }

        return [pscustomobject]@{
            Hostname = $hostname; Company = $companyName
            Status   = "error"; TenantId = ""; Message = ""
            Error    = "No JSON output from provision script"
        }
    }
    catch {
        return [pscustomobject]@{
            Hostname = $hostname; Company = $companyName
            Status   = "error"; TenantId = ""; Message = ""
            Error    = $_.Exception.Message
        }
    }
}

# ── Throttled parallel execution ──────────────────────────────────────────────

$results  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
$jobs     = @()
$i        = 0

foreach ($ep in $endpoints) {
    $i++
    Write-Progress -Activity "Shadow Warden Mass Rollout" `
                   -Status "Queuing $($ep.Hostname) ($i/$total)" `
                   -PercentComplete (($i / $total) * 100)

    $jobs += Start-Job -ScriptBlock $jobBlock `
        -ArgumentList $ep, $GatewayUrl, $MspApiKey, $provisionScript, $DryRun.IsPresent

    # Throttle: wait if too many running
    while (($jobs | Where-Object State -eq "Running").Count -ge $MaxConcurrent) {
        Start-Sleep -Milliseconds 500
    }
}

# ── Collect results ───────────────────────────────────────────────────────────

Write-Host "[MassRollout] All jobs queued. Waiting for completion..." -ForegroundColor Cyan

$jobs | Wait-Job | Out-Null

foreach ($job in $jobs) {
    $r = Receive-Job $job
    if ($r) { $results.Add($r) }
    Remove-Job $job -Force
}

# ── Summary ───────────────────────────────────────────────────────────────────

$resultList = $results | Sort-Object Hostname
$ok         = ($resultList | Where-Object Status -in "ok","dry_run").Count
$skip       = ($resultList | Where-Object Status -eq "already_provisioned").Count
$failed     = ($resultList | Where-Object Status -eq "error").Count

Write-Host ""
Write-Host "──────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host " Shadow Warden Mass Rollout Complete" -ForegroundColor Green
Write-Host "  Total:   $total"
Write-Host "  OK:      $ok"     -ForegroundColor Green
Write-Host "  Skipped: $skip"   -ForegroundColor Yellow
Write-Host "  Failed:  $failed" -ForegroundColor $(if ($failed -gt 0) { "Red" } else { "Green" })
Write-Host "──────────────────────────────────────────" -ForegroundColor DarkGray

if ($failed -gt 0) {
    Write-Host ""
    Write-Host "Failed hosts:" -ForegroundColor Red
    $resultList | Where-Object Status -eq "error" | ForEach-Object {
        Write-Host "  $($_.Hostname) — $($_.Error)" -ForegroundColor Red
    }
}

# Write results CSV
$resultList | Export-Csv -Path $ResultCsvPath -NoTypeInformation -Encoding UTF8
Write-Host ""
Write-Host "[MassRollout] Results saved to: $ResultCsvPath" -ForegroundColor Cyan

exit $(if ($failed -gt 0) { 1 } else { 0 })
