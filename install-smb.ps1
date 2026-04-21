# ─────────────────────────────────────────────────────────────────────────────
# Shadow Warden AI — Community Business Edition
# One-click installer for Windows (PowerShell 5.1+)
#
# Usage (run as Administrator or with Docker Desktop installed):
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\install-smb.ps1
# ─────────────────────────────────────────────────────────────────────────────
param(
    [string]$InstallDir = "$env:USERPROFILE\.shadow-warden-smb",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

function Write-Info    { param($m) Write-Host "[INFO]  $m" -ForegroundColor Cyan }
function Write-Ok      { param($m) Write-Host "[OK]    $m" -ForegroundColor Green }
function Write-Warn    { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err     { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red; exit 1 }

Write-Host ""
Write-Host "  Shadow Warden AI — Community Business Edition" -ForegroundColor White
Write-Host "  One-click security gateway for small and medium businesses" -ForegroundColor Gray
Write-Host "  Version 4.7  |  https://shadow-warden-ai.com" -ForegroundColor Gray
Write-Host ""

# ── Prerequisites ─────────────────────────────────────────────────────────────

Write-Info "Checking prerequisites..."

$docker = Get-Command docker -ErrorAction SilentlyContinue
if (-not $docker) {
    Write-Err "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
}
Write-Ok "Docker found: $(docker --version)"

try {
    docker compose version | Out-Null
} catch {
    Write-Err "Docker Compose V2 not found. Update Docker Desktop to the latest version."
}
Write-Ok "Docker Compose V2 found."

# ── Create install directory ──────────────────────────────────────────────────

Write-Info "Installing to: $InstallDir"
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Set-Location $InstallDir

# ── Generate secrets ──────────────────────────────────────────────────────────

function New-SecureKey {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes).Replace('+','A').Replace('/','B').Replace('=','').Substring(0,43)
}

# ── Write .env.smb ────────────────────────────────────────────────────────────

$envFile = Join-Path $InstallDir ".env.smb"
if ((Test-Path $envFile) -and -not $Force) {
    Write-Warn ".env.smb already exists — skipping key generation (use -Force to regenerate)."
} else {
    Write-Info "Generating .env.smb with secure random keys..."
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm") + " UTC"
    @"
# Shadow Warden AI — Community Business
# Auto-generated $ts
# DO NOT commit this file to version control.

WARDEN_API_KEY=$(New-SecureKey)
VAULT_MASTER_KEY=$(New-SecureKey)
COMMUNITY_VAULT_KEY=$(New-SecureKey)

WARDEN_TIER=community_business
TENANT_ID=my-business

# Optional: Anthropic key enables AI auto-evolution (leave blank for air-gapped mode)
ANTHROPIC_API_KEY=

# Optional: Slack webhook for HIGH/BLOCK alerts
SLACK_WEBHOOK_URL=

FILE_SCAN_ENABLED=true
FILE_SCAN_MAX_MB=10
SHADOW_AI_MONITOR=true
RETENTION_DAYS=180
"@ | Out-File -FilePath $envFile -Encoding utf8
    Write-Ok ".env.smb created."
}

# ── Copy docker-compose.smb.yml ───────────────────────────────────────────────

$composeFile = Join-Path $InstallDir "docker-compose.smb.yml"
$sourceCompose = Join-Path $PSScriptRoot "docker-compose.smb.yml"

if (-not (Test-Path $composeFile)) {
    if (Test-Path $sourceCompose) {
        Copy-Item $sourceCompose $composeFile
        Write-Ok "docker-compose.smb.yml copied."
    } else {
        Write-Err "docker-compose.smb.yml not found. Run this installer from the Shadow Warden project directory."
    }
}

# ── Pull and start ────────────────────────────────────────────────────────────

Write-Info "Pulling Docker images (first run may take 2-3 minutes)..."
docker compose -f $composeFile pull 2>&1 | Out-Null

Write-Info "Starting Shadow Warden AI (Community Business)..."
docker compose -f $composeFile up -d --remove-orphans

# ── Wait for health ───────────────────────────────────────────────────────────

Write-Info "Waiting for warden to be healthy..."
$maxWait = 60; $elapsed = 0; $healthy = $false
while ($elapsed -lt $maxWait) {
    try {
        $r = Invoke-WebRequest -Uri "http://localhost:8001/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        if ($r.StatusCode -eq 200) { $healthy = $true; break }
    } catch {}
    Start-Sleep -Seconds 3; $elapsed += 3; Write-Host -NoNewline "."
}
Write-Host ""

if ($healthy) {
    Write-Ok "Shadow Warden AI is running!"
} else {
    Write-Warn "Warden not responding yet — the AI model may still be loading."
}

# ── Read API key for display ──────────────────────────────────────────────────
$apiKey = (Get-Content $envFile | Where-Object { $_ -match "^WARDEN_API_KEY=" }) -replace "^WARDEN_API_KEY=",""

# ── Summary ───────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host "  ✅  Shadow Warden AI — Community Business ACTIVE" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Green
Write-Host ""
Write-Host "  API Gateway:   http://localhost:8001" -ForegroundColor White
Write-Host "  Dashboard:     http://localhost:8501" -ForegroundColor White
Write-Host "  Health check:  http://localhost:8001/health" -ForegroundColor White
Write-Host "  File Scanner:  POST http://localhost:8001/filter/file" -ForegroundColor White
Write-Host ""
Write-Host "  Your API Key:  $apiKey" -ForegroundColor Yellow
Write-Host "  Config dir:    $InstallDir" -ForegroundColor Gray
Write-Host ""
Write-Host "  Manage:" -ForegroundColor White
Write-Host "  docker compose -f `"$composeFile`" stop" -ForegroundColor Gray
Write-Host "  docker compose -f `"$composeFile`" start" -ForegroundColor Gray
Write-Host "  docker compose -f `"$composeFile`" logs -f warden" -ForegroundColor Gray
Write-Host ""

# Open dashboard in browser
Start-Process "http://localhost:8501"
