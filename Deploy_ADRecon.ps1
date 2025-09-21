# === Active Directory Reconnaissance Deployment ===
# Deploys ADRecon module for domain reconnaissance operations
# Follows Scattered Spider post-exploitation methodology

param(
    [string]$Domain = "",
    [string]$Server = "",
    [string]$OutputDirectory = "C:\Intel\Logs",
    [switch]$AutoExecute = $false,
    [switch]$InstallRSAT = $false
)

Write-Host "========================================" -ForegroundColor Magenta
Write-Host "   AD RECONNAISSANCE DEPLOYMENT" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

$currentPath = Get-Location
$moduleRoot = Join-Path $currentPath "Recon\AD"

Write-Host "[*] Current working directory: $currentPath" -ForegroundColor Gray
Write-Host "[*] AD Recon module path: $moduleRoot" -ForegroundColor Gray
Write-Host ""

# Verify module structure
Write-Host "=== MODULE VERIFICATION ===" -ForegroundColor Cyan
$requiredFiles = @(
    "ADRecon.psm1",
    "Install_RSAT.ps1",
    "Domain Discovery (T1087.002).ps1",
    "Group Policy Discovery (T1615).ps1",
    "Computer Discovery (T1018).ps1",
    "Trust Discovery (T1482).ps1"
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
    Write-Error "Required ADRecon module files are missing. Deployment cannot continue."
    exit 1
}

Write-Host ""

# Check and install RSAT if requested
if ($InstallRSAT) {
    Write-Host "=== RSAT INSTALLATION ===" -ForegroundColor Cyan
    Write-Host "[*] Installing Remote Server Administration Tools..." -ForegroundColor Yellow
    
    $rsatScript = Join-Path $moduleRoot "Install_RSAT.ps1"
    try {
        & $rsatScript
        Write-Host "[+] RSAT installation completed" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] RSAT installation failed: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "[!] Manual RSAT installation may be required" -ForegroundColor Yellow
    }
    Write-Host ""
}

# Import the ADRecon module
Write-Host "=== MODULE DEPLOYMENT ===" -ForegroundColor Cyan
Write-Host "[*] Importing ADRecon PowerShell module..." -ForegroundColor Yellow

$modulePath = Join-Path $moduleRoot "ADRecon.psm1"
try {
    Import-Module $modulePath -Force -DisableNameChecking
    Write-Host "[+] ADRecon module imported successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to import ADRecon module: $($_.Exception.Message)"
    exit 1
}

# Configure module settings
if ($Domain -or $Server -or $OutputDirectory) {
    Write-Host "[*] Configuring module settings..." -ForegroundColor Yellow
    Set-ADReconConfig -Domain $Domain -Server $Server -OutputDirectory $OutputDirectory
}

# Verify Active Directory connectivity
Write-Host "[*] Verifying Active Directory connectivity..." -ForegroundColor Yellow
try {
    if (Get-Module -Name ActiveDirectory -ListAvailable) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        $currentDomain = Get-ADDomain -ErrorAction SilentlyContinue
        if ($currentDomain) {
            Write-Host "[+] Connected to domain: $($currentDomain.DNSRoot)" -ForegroundColor Green
        } else {
            Write-Host "[!] Not connected to an Active Directory domain" -ForegroundColor Yellow
        }
    } else {
        Write-Host "[!] Active Directory module not available" -ForegroundColor Yellow
        Write-Host "[!] Run with -InstallRSAT to install required tools" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "[!] AD connectivity check failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

Write-Host ""

# Display available functions
Write-Host "=== AVAILABLE COMMANDS ===" -ForegroundColor Cyan
Write-Host "Core Functions:" -ForegroundColor Yellow
Write-Host "  Install-RSATTools              - Install Active Directory tools" -ForegroundColor White
Write-Host "  Invoke-FullADReconnaissance    - Execute complete AD reconnaissance" -ForegroundColor White
Write-Host "  Run-ADRecon                    - Alias for full reconnaissance" -ForegroundColor White
Write-Host "  Get-ADReconResults             - View reconnaissance results" -ForegroundColor White
Write-Host "  Get-ADResults                  - Alias for results viewing" -ForegroundColor White
Write-Host ""
Write-Host "Individual Techniques:" -ForegroundColor Yellow
Write-Host "  Invoke-DomainUserDiscovery     - Domain user enumeration (T1087.002)" -ForegroundColor White
Write-Host "  Invoke-GroupPolicyDiscovery    - Group Policy analysis (T1615)" -ForegroundColor White
Write-Host "  Invoke-ComputerDiscovery       - Domain computer enumeration (T1018)" -ForegroundColor White
Write-Host "  Invoke-TrustDiscovery          - Domain trust analysis (T1482)" -ForegroundColor White
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Set-ADReconConfig -Domain <domain> -Server <server>" -ForegroundColor White
Write-Host ""

# Auto-execute if requested
if ($AutoExecute) {
    Write-Host "=== AUTO-EXECUTION ===" -ForegroundColor Cyan
    Write-Host "[*] Auto-executing full AD reconnaissance..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        Invoke-FullADReconnaissance -Domain $Domain -Server $Server
    }
    catch {
        Write-Host "[!] Auto-execution failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "   DEPLOYMENT COMPLETE" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "ADRecon module is now ready for use!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor Yellow
    Write-Host "  Run-ADRecon                    # Execute all techniques" -ForegroundColor Gray
    Write-Host "  Get-ADResults                  # View results" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Output Location: $OutputDirectory" -ForegroundColor Cyan
    
    # Prompt for immediate execution
    Write-Host ""
    $executeNow = Read-Host "Execute AD reconnaissance now? (Y/n)"
    if ($executeNow -eq "" -or $executeNow -eq "Y" -or $executeNow -eq "y") {
        Write-Host ""
        Write-Host "[*] Executing full AD reconnaissance..." -ForegroundColor Cyan
        try {
            Invoke-FullADReconnaissance -Domain $Domain -Server $Server
        }
        catch {
            Write-Host "[!] Execution failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}