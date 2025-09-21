# === Pre-Exploitation Git Installer ===
# Ensures Git CLI is available for repository cloning post-AnyDesk
# Auto-detects privileges and installs accordingly

param(
    [switch]$Force = $false,
    [switch]$Quiet = $false
)

function Write-Status {
    param([string]$Message, [string]$Color = "White")
    if (-not $Quiet) {
        Write-Host $Message -ForegroundColor $Color
    }
}

function Test-GitInstalled {
    try {
        $null = git --version 2>$null
        return $LASTEXITCODE -eq 0
    }
    catch {
        return $false
    }
}

function Test-AdminPrivileges {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

Write-Status "[*] Pre-Exploitation: Ensuring Git CLI availability..." "Cyan"

# Step 1: Check if Git is already installed
if ((Test-GitInstalled) -and (-not $Force)) {
    $gitVersion = git --version 2>$null
    Write-Status "[+] Git already installed: $gitVersion" "Green"
    Write-Status "[+] Pre-exploitation requirement satisfied!" "Green"
    exit 0
}

if ($Force) {
    Write-Status "[*] Force flag specified, reinstalling Git..." "Yellow"
}

# Step 2: Check privileges and determine installation method
$isAdmin = Test-AdminPrivileges
Write-Status "[*] Admin privileges detected: $isAdmin" "Yellow"

if ($isAdmin) {
    Write-Status "[*] Using system-wide installation (admin privileges available)..." "Cyan"
    $scriptPath = Join-Path $PSScriptRoot "Downloading_Git_Systemwide.ps1"
    
    if (Test-Path $scriptPath) {
        try {
            Write-Status "[*] Executing system-wide Git installation..." "Cyan"
            & $scriptPath
            
            # Verify installation
            Start-Sleep -Seconds 5
            if (Test-GitInstalled) {
                $gitVersion = git --version 2>$null
                Write-Status "[+] System-wide Git installation successful: $gitVersion" "Green"
            } else {
                throw "Git installation completed but git command not available"
            }
        }
        catch {
            Write-Status "[!] System-wide installation failed: $($_.Exception.Message)" "Red"
            Write-Status "[*] Falling back to user-level installation..." "Yellow"
            $isAdmin = $false  # Force user-level fallback
        }
    } else {
        Write-Status "[!] System-wide installer not found, using user-level installation..." "Yellow"
        $isAdmin = $false
    }
}

if (-not $isAdmin) {
    Write-Status "[*] Using user-level installation (portable)..." "Cyan"
    $scriptPath = Join-Path $PSScriptRoot "Downloading_Git.ps1"
    
    if (Test-Path $scriptPath) {
        try {
            Write-Status "[*] Executing user-level Git installation..." "Cyan"
            & $scriptPath
            
            # Verify installation
            Start-Sleep -Seconds 5
            if (Test-GitInstalled) {
                $gitVersion = git --version 2>$null
                Write-Status "[+] User-level Git installation successful: $gitVersion" "Green"
            } else {
                throw "Git installation completed but git command not available"
            }
        }
        catch {
            Write-Status "[!] User-level installation failed: $($_.Exception.Message)" "Red"
            Write-Status "[!] Pre-exploitation requirement NOT satisfied!" "Red"
            exit 1
        }
    } else {
        Write-Status "[!] User-level installer not found at: $scriptPath" "Red"
        Write-Status "[!] Pre-exploitation requirement NOT satisfied!" "Red"
        exit 1
    }
}

Write-Status ""
Write-Status "[+] ===== PRE-EXPLOITATION COMPLETE =====" "Green"
Write-Status "[+] Git CLI is now available for repository operations" "Green"
Write-Status "[+] Ready for payload delivery and reconnaissance deployment" "Green"

# Test final Git functionality
try {
    $gitVersion = git --version
    $gitPath = (Get-Command git -ErrorAction SilentlyContinue).Source
    Write-Status "[+] Git Version: $gitVersion" "Green"
    Write-Status "[+] Git Location: $gitPath" "Green"
}
catch {
    Write-Status "[!] Warning: Git may not be immediately available in new sessions" "Yellow"
    Write-Status "[!] May require PowerShell restart or PATH refresh" "Yellow"
}