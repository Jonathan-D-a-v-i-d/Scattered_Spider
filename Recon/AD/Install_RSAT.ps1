# === RSAT Installation for Active Directory Reconnaissance ===
# Installs Remote Server Administration Tools for AD PowerShell cmdlets
# Required for domain reconnaissance capabilities

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

function Test-RSATInstalled {
    try {
        # Check if AD module is available
        $adModule = Get-Module -Name ActiveDirectory -ListAvailable -ErrorAction SilentlyContinue
        return $null -ne $adModule
    }
    catch {
        return $false
    }
}

function Test-AdminPrivileges {
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

Write-Status "[*] Active Directory Reconnaissance: Installing RSAT..." "Cyan"

# Check if RSAT is already installed
if ((Test-RSATInstalled) -and (-not $Force)) {
    Write-Status "[+] RSAT Active Directory module already available" "Green"
    Write-Status "[+] AD reconnaissance capabilities ready!" "Green"
    exit 0
}

if ($Force) {
    Write-Status "[*] Force flag specified, reinstalling RSAT..." "Yellow"
}

# Check admin privileges (required for RSAT installation)
if (-not (Test-AdminPrivileges)) {
    Write-Status "[!] RSAT installation requires Administrator privileges" "Red"
    Write-Status "[!] Please run PowerShell as Administrator and try again" "Red"
    exit 1
}

Write-Status "[*] Installing RSAT Active Directory tools..." "Cyan"

try {
    # Windows 10/11 method - Install RSAT as Windows capability
    $rsatFeature = "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    
    Write-Status "[*] Checking Windows capabilities..." "Cyan"
    $capability = Get-WindowsCapability -Online | Where-Object { $_.Name -eq $rsatFeature }
    
    if ($capability) {
        if ($capability.State -eq "Installed") {
            Write-Status "[+] RSAT AD capability already installed" "Green"
        } else {
            Write-Status "[*] Installing RSAT AD capability..." "Cyan"
            Add-WindowsCapability -Online -Name $rsatFeature -ErrorAction Stop
            Write-Status "[+] RSAT AD capability installation completed" "Green"
        }
    } else {
        # Fallback method for older systems
        Write-Status "[*] Using alternative RSAT installation method..." "Yellow"
        
        # Try PowerShell Get-WindowsFeature (Server systems)
        try {
            Import-Module ServerManager -ErrorAction Stop
            $feature = Get-WindowsFeature -Name "RSAT-AD-PowerShell" -ErrorAction Stop
            
            if ($feature.InstallState -eq "Installed") {
                Write-Status "[+] RSAT AD PowerShell already installed" "Green"
            } else {
                Write-Status "[*] Installing RSAT AD PowerShell feature..." "Cyan"
                Install-WindowsFeature -Name "RSAT-AD-PowerShell" -ErrorAction Stop
                Write-Status "[+] RSAT AD PowerShell feature installation completed" "Green"
            }
        }
        catch {
            # Final fallback - try DISM
            Write-Status "[*] Attempting DISM installation method..." "Yellow"
            $dismResult = & dism.exe /online /add-capability /capabilityname:Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-Status "[+] DISM RSAT installation completed" "Green"
            } else {
                throw "DISM installation failed: $($dismResult -join ' ')"
            }
        }
    }
    
    # Wait a moment for installation to complete
    Start-Sleep -Seconds 3
    
    # Verify installation
    if (Test-RSATInstalled) {
        Write-Status "[+] RSAT Active Directory module successfully installed" "Green"
        
        # Import the module to verify functionality
        try {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Status "[+] Active Directory module imported successfully" "Green"
            
            # Test basic AD connectivity (if in domain)
            try {
                $domain = Get-ADDomain -ErrorAction SilentlyContinue
                if ($domain) {
                    Write-Status "[+] Domain connectivity verified: $($domain.DNSRoot)" "Green"
                } else {
                    Write-Status "[!] No domain connection (standalone system or connectivity issues)" "Yellow"
                }
            }
            catch {
                Write-Status "[!] Domain connectivity test failed (may be normal for standalone systems)" "Yellow"
            }
        }
        catch {
            Write-Status "[!] Warning: AD module installed but import failed" "Yellow"
            Write-Status "[!] May require PowerShell restart or system reboot" "Yellow"
        }
    } else {
        throw "RSAT installation completed but AD module not detected"
    }
    
    Write-Status ""
    Write-Status "[+] ===== AD RECONNAISSANCE READY =====" "Green"
    Write-Status "[+] RSAT Active Directory tools installed" "Green"
    Write-Status "[+] PowerShell AD cmdlets now available" "Green"
    Write-Status "[+] Ready for domain reconnaissance operations" "Green"
    
}
catch {
    Write-Status "[!] RSAT installation failed: $($_.Exception.Message)" "Red"
    Write-Status "[!] AD reconnaissance capabilities may be limited" "Red"
    Write-Status "[!] Manual RSAT installation may be required" "Red"
    exit 1
}

# Display available AD cmdlets for reference
if (-not $Quiet) {
    Write-Status ""
    Write-Status "Key AD Cmdlets Now Available:" "Yellow"
    Write-Status "- Get-ADDomain, Get-ADForest" "Gray"
    Write-Status "- Get-ADUser, Get-ADGroup" "Gray"
    Write-Status "- Get-ADComputer, Get-ADDomainController" "Gray"
    Write-Status "- Get-ADGroupMember, Get-ADOrganizationalUnit" "Gray"
    Write-Status "- Get-ADTrust, Get-ADReplicationSite" "Gray"
}