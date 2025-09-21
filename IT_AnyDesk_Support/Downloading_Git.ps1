# === Git Portable Installer Script (No Admin Required) ===
# Downloads and sets up Git portable in user directory

Write-Host "Getting latest Git for Windows portable release..."

# Step 1: Get the latest release download URL for portable version
try {
    $latestRelease = Invoke-RestMethod -Uri "https://api.github.com/repos/git-for-windows/git/releases/latest" -UseBasicParsing
    $GitPortableUrl = ($latestRelease.assets | Where-Object { $_.name -match "PortableGit-.*-64-bit\.7z\.exe$" }).browser_download_url
    
    if (-not $GitPortableUrl) {
        throw "Could not find 64-bit Git portable installer in latest release"
    }
    
    Write-Host "Found latest version: $($latestRelease.tag_name)"
} catch {
    Write-Error "Failed to get latest Git release: $($_.Exception.Message)"
    exit 1
}

# Step 2: Define installation paths
$GitDir = "$env:USERPROFILE\Git"
$PortableInstallerPath = "$env:TEMP\GitPortable.exe"

Write-Host "Downloading Git portable from $GitPortableUrl..."

# Step 3: Download portable installer
try {
    Invoke-WebRequest -Uri $GitPortableUrl -OutFile $PortableInstallerPath -UseBasicParsing
    Write-Host "Download complete. Extracting Git..."
} catch {
    Write-Error "Failed to download Git portable: $($_.Exception.Message)"
    exit 1
}

# Step 4: Create Git directory if it doesn't exist
if (Test-Path $GitDir) {
    Write-Host "Removing existing Git installation at $GitDir..."
    Remove-Item $GitDir -Recurse -Force
}

New-Item -ItemType Directory -Path $GitDir -Force | Out-Null

# Step 5: Extract portable Git (it's a self-extracting archive)
try {
    Write-Host "Extracting to $GitDir..."
    $extractProcess = Start-Process -FilePath $PortableInstallerPath -ArgumentList "-o`"$GitDir`"", "-y" -Wait -PassThru -WindowStyle Hidden
    if ($extractProcess.ExitCode -ne 0) {
        throw "Extractor returned exit code: $($extractProcess.ExitCode)"
    }
} catch {
    Write-Error "Failed to extract Git: $($_.Exception.Message)"
    Remove-Item $PortableInstallerPath -Force -ErrorAction SilentlyContinue
    exit 1
}

# Step 6: Cleanup installer
Remove-Item $PortableInstallerPath -Force

# Step 7: Add Git to user PATH
$GitBinPath = "$GitDir\bin"
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")

if ($UserPath -notlike "*$GitBinPath*") {
    Write-Host "Adding Git to user PATH..."
    $NewPath = if ($UserPath) { "$UserPath;$GitBinPath" } else { $GitBinPath }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
    
    # Update current session PATH
    $env:Path = "$env:Path;$GitBinPath"
} else {
    Write-Host "Git already in user PATH."
}

Write-Host "Git portable installation complete at: $GitDir"

# Step 8: Verify installation
try {
    $gitVersion = & "$GitBinPath\git.exe" --version 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Installed: $gitVersion"
        Write-Host "Git executable location: $GitBinPath\git.exe"
    } else {
        Write-Warning "Git installed but verification failed. Try restarting PowerShell."
    }
} catch {
    Write-Warning "Git installed but not immediately available. Restart PowerShell or use full path: $GitBinPath\git.exe"
}

Write-Host ""
Write-Host "Usage notes:"
Write-Host "- Git installed to: $GitDir"
Write-Host "- Added to user PATH (restart PowerShell if 'git' command not found)"
Write-Host "- No admin privileges required"
Write-Host "- To uninstall: delete $GitDir and remove from PATH"