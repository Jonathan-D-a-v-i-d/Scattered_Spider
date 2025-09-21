# Victim Host Recon Deployment Script
# Quick deployment for security simulation scenarios

Write-Host "========================================" -ForegroundColor Red
Write-Host " VICTIM HOST - RECON DEPLOYMENT" -ForegroundColor Red  
Write-Host "========================================" -ForegroundColor Red
Write-Host ""

# Check if running from correct directory
$currentPath = Get-Location
if (!(Test-Path ".\Recon\Host\VictimHostRecon.psm1")) {
    Write-Error "Must run from Scattered_Spider root directory. Current: $currentPath"
    Write-Host "Usage: git clone repo, then run .\Deploy_VictimHostRecon.ps1"
    exit 1
}

# Step 1: Verify Git CLI is available (should be installed during initial deployment)
Write-Host "[*] Verifying Git CLI availability..." -ForegroundColor Cyan

try {
    $null = git --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Git CLI is available" -ForegroundColor Green
    } else {
        Write-Warning "Git CLI not found. Repository operations may be limited."
        Write-Host "[!] Ensure initial deployment completed successfully" -ForegroundColor Yellow
    }
}
catch {
    Write-Warning "Git CLI not found. Repository operations may be limited."
    Write-Host "[!] Ensure initial deployment completed successfully" -ForegroundColor Yellow
}

Write-Host "[*] Loading Victim Host Recon Module..." -ForegroundColor Cyan

try {
    # Import the recon module
    Import-Module ".\Recon\Host\VictimHostRecon.psm1" -Force
    Write-Host "[+] Module loaded successfully!" -ForegroundColor Green
    
    # Show available commands
    Write-Host ""
    Write-Host "Available Commands:" -ForegroundColor Yellow
    Write-Host "- Invoke-FullReconnaissance  (or Run-Recon)" -ForegroundColor White
    Write-Host "- Invoke-SystemInfoDiscovery (or Get-HostInfo)" -ForegroundColor White
    Write-Host "- Invoke-AccountDiscovery" -ForegroundColor White
    Write-Host "- Invoke-ProcessDiscovery" -ForegroundColor White
    Write-Host "- Invoke-SoftwareDiscovery" -ForegroundColor White
    Write-Host "- Invoke-NetworkServiceDiscovery" -ForegroundColor White
    Write-Host "- Invoke-FileDirectoryDiscovery" -ForegroundColor White
    Write-Host "- Get-ReconResults" -ForegroundColor White
    
    Write-Host ""
    Write-Host "Quick Start Examples:" -ForegroundColor Cyan
    Write-Host "  Run-Recon                    # Execute all reconnaissance" -ForegroundColor Gray
    Write-Host "  Get-HostInfo                 # System information only" -ForegroundColor Gray
    Write-Host "  Get-ReconResults             # View results summary" -ForegroundColor Gray
    
    Write-Host ""
    $choice = Read-Host "Execute full victim host reconnaissance now? (y/N)"
    
    if ($choice -eq 'y' -or $choice -eq 'Y') {
        Write-Host ""
        Write-Host "[*] Starting full victim host reconnaissance..." -ForegroundColor Green
        Invoke-FullReconnaissance
    }
    else {
        Write-Host "[*] Module ready. Use commands above to start victim host reconnaissance." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed to load module: $($_.Exception.Message)"
    exit 1
}

Write-Host ""
Write-Host "[+] Deployment complete!" -ForegroundColor Green