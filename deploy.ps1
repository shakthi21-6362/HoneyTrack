<#
.SYNOPSIS
    HoneyTrack 1-Command Docker Deployment Script for Windows PowerShell
.DESCRIPTION
    Builds, configures and runs HoneyTrack inside Docker on Windows with a single command.
    Supports both default SQLite and enterprise TimescaleDB / PostgreSQL time-series backends.
.EXAMPLE
    .\deploy.ps1
    .\deploy.ps1 -Mode timescale
    .\deploy.ps1 -Mode prod
    .\deploy.ps1 -Mode timescale-prod
    .\deploy.ps1 -Mode down
    .\deploy.ps1 -Mode logs
#>
param (
    [ValidateSet("demo", "prod", "timescale", "timescale-prod", "down", "logs")]
    [string]$Mode = "demo"
)

Write-Host "  _   _                        _____               _    " -ForegroundColor Cyan
Write-Host " | | | | ___  _ __   ___ _   _|_   _| __ __ _  ___| | __" -ForegroundColor Cyan
Write-Host " | |_| |/ _ \| '_ \ / _ \ | | | | | | '__/ _` |/ __| |/ /" -ForegroundColor Cyan
Write-Host " |  _  | (_) | | | |  __/ |_| | | | | | | (_| | (__|   < " -ForegroundColor Cyan
Write-Host " |_| |_|\___/|_| |_|\___|\__, | |_| |_|  \__,_|\___|_|\_\" -ForegroundColor Cyan
Write-Host "                          |___/                          " -ForegroundColor Cyan
Write-Host "==> HoneyTrack Docker 1-Command Windows Deployment <==" -ForegroundColor Green
Write-Host ""

# 1. Check if Docker is running
try {
    docker version > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Docker does not appear to be running. Please start Docker Desktop first." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "[!] Docker command failed. Ensure Docker Desktop is installed and in your PATH." -ForegroundColor Red
    exit 1
}

# 2. Handle subcommands
if ($Mode -eq "down") {
    Write-Host "[*] Stopping HoneyTrack..." -ForegroundColor Yellow
    docker compose --profile timescale down
    Write-Host "[+] HoneyTrack stopped." -ForegroundColor Green
    exit 0
}

if ($Mode -eq "logs") {
    docker compose logs -f
    exit 0
}

# 3. Ensure .env exists with cryptographic secret
if (-not (Test-Path ".env")) {
    Write-Host "[!] .env not found. Generating from .env.example..." -ForegroundColor Yellow
    if (Test-Path ".env.example") {
        Copy-Item ".env.example" ".env"
    } else {
        New-Item -ItemType File -Path ".env" | Out-Null
    }
    
    # Generate 32-byte hex random string
    $bytes = New-Object byte[] 32
    (New-Object System.Security.Cryptography.RNGCryptoServiceProvider).GetBytes($bytes)
    $randKey = ($bytes | ForEach-Object { "{0:x2}" -f $_ }) -join ""
    
    $content = Get-Content ".env" -Raw
    if ($content -match "SECRET_KEY=.*") {
        $content = $content -replace "SECRET_KEY=.*", "SECRET_KEY=$randKey"
    } else {
        $content += "`nSECRET_KEY=$randKey"
    }
    Set-Content -Path ".env" -Value $content
    Write-Host "[+] Created .env file with secure SECRET_KEY." -ForegroundColor Green
}

# 4. Create persistent volume folders
if (-not (Test-Path "data")) { New-Item -ItemType Directory -Path "data" | Out-Null }
if (-not (Test-Path "ssh_keys")) { New-Item -ItemType Directory -Path "ssh_keys" | Out-Null }

# 5. Launch containers
switch ($Mode) {
    "timescale" {
        Write-Host "[*] Launching HoneyTrack with TimescaleDB / PostgreSQL time-series backend (DEMO mode)..." -ForegroundColor Cyan
        docker compose --profile timescale up -d
    }
    "timescale-prod" {
        Write-Host "[*] Launching HoneyTrack with TimescaleDB / PostgreSQL backend (PRODUCTION mode)..." -ForegroundColor Cyan
        docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile timescale up -d
    }
    "prod" {
        Write-Host "[*] Launching in PRODUCTION mode (live listeners only, SQLite)..." -ForegroundColor Cyan
        docker compose -f docker-compose.yml -f docker-compose.prod.yml --profile default up -d
    }
    default {
        Write-Host "[*] Launching in DEMO mode (live listeners + background attack feed, SQLite)..." -ForegroundColor Cyan
        docker compose --profile default up -d
    }
}

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "===================================================================" -ForegroundColor Green
    Write-Host " [✓] HoneyTrack deployed successfully!" -ForegroundColor Green
    Write-Host "===================================================================" -ForegroundColor Green
    Write-Host "  Dashboard URL:      http://localhost:5000" -ForegroundColor Cyan
    Write-Host "  SSH Honeypot:       localhost:2222" -ForegroundColor Yellow
    Write-Host "  HTTP Honeypot:      localhost:8080" -ForegroundColor Yellow
    Write-Host "  FTP Honeypot:       localhost:2121" -ForegroundColor Yellow
    if ($Mode -like "*timescale*") {
        Write-Host "  TimescaleDB:        localhost:5432 (hypertables active)" -ForegroundColor Green
    }
    Write-Host ""
    Write-Host "  View live logs:     .\deploy.ps1 -Mode logs" -ForegroundColor Gray
    Write-Host "  Stop containers:    .\deploy.ps1 -Mode down" -ForegroundColor Gray
    Write-Host "===================================================================" -ForegroundColor Green
} else {
    Write-Host "[!] Docker Compose build or startup failed. Check error above." -ForegroundColor Red
}
