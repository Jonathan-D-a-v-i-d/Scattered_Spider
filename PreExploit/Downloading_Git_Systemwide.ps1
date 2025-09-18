# === Git for Windows Installer Script ===
# Run this as Administrator on Windows 11

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
    exit 1
}

Write-Host "Getting latest Git for Windows release..."

# Step 1: Get the latest release download URL
try {
    $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest" -UseBasicParsing
    $GitInstallerUrl = ($latestRelease.assets | Where-Object { $_.name -match "Git-.*-64-bit\.exe$" }).browser_download_url
    
    if (-not $GitInstallerUrl) {
        throw "Could not find 64-bit Git installer in latest release"
    }
    
    Write-Host "Found latest version: $($latestRelease.tag_name)"
} catch {
    Write-Error "Failed to get latest Git release: $($_.Exception.Message)"
    exit 1
}

$InstallerPath = "$env:TEMP\GitInstaller.exe"

Write-Host "Downloading Git installer from $GitInstallerUrl..."

# Step 2: Download installer
try {
    Invoke-WebRequest -Uri $GitInstallerUrl -OutFile $InstallerPath -UseBasicParsing
    Write-Host "Download complete. Installing Git..."
} catch {
    Write-Error "Failed to download Git installer: $($_.Exception.Message)"
    exit 1
}

# Step 3: Run the installer silently
try {
    $installProcess = Start-Process -FilePath $InstallerPath -ArgumentList "/VERYSILENT /NORESTART" -Wait -PassThru
    if ($installProcess.ExitCode -ne 0) {
        throw "Installer returned exit code: $($installProcess.ExitCode)"
    }
} catch {
    Write-Error "Failed to install Git: $($_.Exception.Message)"
    Remove-Item $InstallerPath -Force -ErrorAction SilentlyContinue
    exit 1
}

# Step 4: Cleanup installer
Remove-Item $InstallerPath -Force

Write-Host "Git installation complete."

# Step 5: Refresh environment variables and verify installation
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

try {
    $gitVersion = & git --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Installed: $gitVersion"
    } else {
        Write-Warning "Git installed but not immediately available. You may need to restart your PowerShell session."
    }
} catch {
    Write-Warning "Git installed but not immediately available. You may need to restart your PowerShell session."
}
