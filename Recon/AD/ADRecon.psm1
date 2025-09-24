# ========================================
#   ADRecon PowerShell Module
#   Active Directory Reconnaissance
# ========================================

# Global configuration
$global:ADReconConfig = @{
    OutputDirectory = "C:\Intel\Logs"
    Prefix = "ADRecon_"
    Domain = ""
    Server = ""
}

# Import required modules function
function Import-RequiredModules {
    try {
        if (Get-Module -Name ActiveDirectory -ListAvailable) {
            Import-Module ActiveDirectory -ErrorAction Stop -WarningAction SilentlyContinue
            return $true
        } else {
            Write-Host "Active Directory module not available" -ForegroundColor Red
            Write-Host "Run Install-RSATTools to install required components" -ForegroundColor Red
            return $false
        }
    }
    catch {
        Write-Host "Failed to import Active Directory module: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# RSAT Installation
function Install-RSATTools {
    <#
    .SYNOPSIS
    Installs Remote Server Administration Tools for Active Directory
    .DESCRIPTION
    Installs RSAT components required for AD reconnaissance operations
    #>
    
    $scriptPath = Join-Path $PSScriptRoot "Install_RSAT.ps1"
    if (Test-Path $scriptPath) {
        & $scriptPath
    } else {
        Write-Error "Install_RSAT.ps1 not found in module directory"
    }
}

# Domain User Discovery (T1087.002)
function Invoke-DomainUserDiscovery {
    <#
    .SYNOPSIS
    Enumerates domain users with focus on privileged accounts
    .DESCRIPTION
    Maps to MITRE ATT&CK T1087.002 - Account Discovery: Domain Account
    #>
    param(
        [int]$MaxUsers = 1000,
        [switch]$PrivilegedOnly = $false
    )
    
    if (-not (Import-RequiredModules)) { return }
    
    $scriptPath = Join-Path $PSScriptRoot "Domain Discovery (T1087.002).ps1"
    if (Test-Path $scriptPath) {
        $results = & $scriptPath -Domain $global:ADReconConfig.Domain -Server $global:ADReconConfig.Server -MaxUsers $MaxUsers -PrivilegedOnly:$PrivilegedOnly
        
        # Save results
        $outputFile = Join-Path $global:ADReconConfig.OutputDirectory "$($global:ADReconConfig.Prefix)DomainUserDiscovery.txt"
        Ensure-OutputDirectory
        $results | Format-Table -AutoSize | Out-String | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "✓ Results saved to: $outputFile" -ForegroundColor Green
        
        return $results
    } else {
        Write-Error "Domain Discovery script not found"
    }
}

# Group Policy Discovery (T1615)
function Invoke-GroupPolicyDiscovery {
    <#
    .SYNOPSIS
    Enumerates Group Policy Objects and settings
    .DESCRIPTION
    Maps to MITRE ATT&CK T1615 - Group Policy Discovery
    #>
    param(
        [switch]$Detailed = $false
    )
    
    if (-not (Import-RequiredModules)) { return }
    
    $scriptPath = Join-Path $PSScriptRoot "Group Policy Discovery (T1615).ps1"
    if (Test-Path $scriptPath) {
        $results = & $scriptPath -Domain $global:ADReconConfig.Domain -Server $global:ADReconConfig.Server -Detailed:$Detailed
        
        # Save results
        $outputFile = Join-Path $global:ADReconConfig.OutputDirectory "$($global:ADReconConfig.Prefix)GroupPolicyDiscovery.txt"
        Ensure-OutputDirectory
        $results | Format-Table -AutoSize | Out-String | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "✓ Results saved to: $outputFile" -ForegroundColor Green
        
        return $results
    } else {
        Write-Error "Group Policy Discovery script not found"
    }
}

# Computer Discovery (T1018)
function Invoke-ComputerDiscovery {
    <#
    .SYNOPSIS
    Enumerates domain computers and potential targets
    .DESCRIPTION
    Maps to MITRE ATT&CK T1018 - Remote System Discovery
    #>
    param(
        [int]$MaxComputers = 1000,
        [switch]$ServersOnly = $false
    )
    
    if (-not (Import-RequiredModules)) { return }
    
    $scriptPath = Join-Path $PSScriptRoot "Computer Discovery (T1018).ps1"
    if (Test-Path $scriptPath) {
        $results = & $scriptPath -Domain $global:ADReconConfig.Domain -Server $global:ADReconConfig.Server -MaxComputers $MaxComputers -ServersOnly:$ServersOnly
        
        # Save results
        $outputFile = Join-Path $global:ADReconConfig.OutputDirectory "$($global:ADReconConfig.Prefix)ComputerDiscovery.txt"
        Ensure-OutputDirectory
        $results | Format-Table -AutoSize | Out-String | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "✓ Results saved to: $outputFile" -ForegroundColor Green
        
        return $results
    } else {
        Write-Error "Computer Discovery script not found"
    }
}

# Trust Discovery (T1482)
function Invoke-TrustDiscovery {
    <#
    .SYNOPSIS
    Enumerates domain trusts for lateral movement paths
    .DESCRIPTION
    Maps to MITRE ATT&CK T1482 - Domain Trust Discovery
    #>
    param(
        [switch]$Detailed = $false
    )
    
    if (-not (Import-RequiredModules)) { return }
    
    $scriptPath = Join-Path $PSScriptRoot "Trust Discovery (T1482).ps1"
    if (Test-Path $scriptPath) {
        $results = & $scriptPath -Domain $global:ADReconConfig.Domain -Server $global:ADReconConfig.Server -Detailed:$Detailed
        
        # Save results
        $outputFile = Join-Path $global:ADReconConfig.OutputDirectory "$($global:ADReconConfig.Prefix)TrustDiscovery.txt"
        Ensure-OutputDirectory
        $results | Format-Table -AutoSize | Out-String | Out-File -FilePath $outputFile -Encoding UTF8
        Write-Host "✓ Results saved to: $outputFile" -ForegroundColor Green
        
        return $results
    } else {
        Write-Error "Trust Discovery script not found"
    }
}

# Full AD Reconnaissance
function Invoke-FullADReconnaissance {
    <#
    .SYNOPSIS
    Executes complete Active Directory reconnaissance
    .DESCRIPTION
    Runs all AD reconnaissance techniques and generates comprehensive report
    #>
    param(
        [string]$Domain = "",
        [string]$Server = "",
        [switch]$Detailed = $false
    )
    
    if ($Domain) { $global:ADReconConfig.Domain = $Domain }
    if ($Server) { $global:ADReconConfig.Server = $Server }
    
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "  ACTIVE DIRECTORY RECONNAISSANCE" -ForegroundColor Magenta  
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host ""
    
    # Check RSAT availability
    if (-not (Import-RequiredModules)) {
        Write-Host "[!] RSAT Active Directory module required" -ForegroundColor Red
        Write-Host "[?] Install RSAT tools? (Y/n): " -NoNewline -ForegroundColor Yellow
        $install = Read-Host
        if ($install -eq "" -or $install -eq "Y" -or $install -eq "y") {
            Install-RSATTools
            if (-not (Import-RequiredModules)) {
                Write-Error "RSAT installation failed or requires restart"
                return
            }
        } else {
            Write-Error "RSAT required for AD reconnaissance"
            return
        }
    }
    
    Ensure-OutputDirectory
    
    $allResults = @()
    $startTime = Get-Date
    
    Write-Host "[*] Starting comprehensive AD reconnaissance..." -ForegroundColor Cyan
    Write-Host "[*] Target Domain: $(if($global:ADReconConfig.Domain) { $global:ADReconConfig.Domain } else { 'Current Domain' })" -ForegroundColor Gray
    Write-Host "[*] Output Directory: $($global:ADReconConfig.OutputDirectory)" -ForegroundColor Gray
    Write-Host ""
    
    # Domain User Discovery
    Write-Host "=== Domain User Discovery (T1087.002) ===" -ForegroundColor Yellow
    try {
        $userResults = Invoke-DomainUserDiscovery
        $allResults += @{ Technique = "Domain User Discovery"; Results = $userResults; Count = $userResults.Count }
        Write-Host "✓ Completed: Found $($userResults.Count) users" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed: $($_.Exception.Message)" -ForegroundColor Red
        $allResults += @{ Technique = "Domain User Discovery"; Results = @(); Count = 0; Error = $_.Exception.Message }
    }
    Write-Host ""
    
    # Group Policy Discovery
    Write-Host "=== Group Policy Discovery (T1615) ===" -ForegroundColor Yellow
    try {
        $gpoResults = Invoke-GroupPolicyDiscovery -Detailed:$Detailed
        $allResults += @{ Technique = "Group Policy Discovery"; Results = $gpoResults; Count = $gpoResults.Count }
        Write-Host "✓ Completed: Found $($gpoResults.Count) GPO entries" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed: $($_.Exception.Message)" -ForegroundColor Red
        $allResults += @{ Technique = "Group Policy Discovery"; Results = @(); Count = 0; Error = $_.Exception.Message }
    }
    Write-Host ""
    
    # Computer Discovery
    Write-Host "=== Computer Discovery (T1018) ===" -ForegroundColor Yellow
    try {
        $computerResults = Invoke-ComputerDiscovery
        $allResults += @{ Technique = "Computer Discovery"; Results = $computerResults; Count = $computerResults.Count }
        Write-Host "✓ Completed: Found $($computerResults.Count) computers" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed: $($_.Exception.Message)" -ForegroundColor Red
        $allResults += @{ Technique = "Computer Discovery"; Results = @(); Count = 0; Error = $_.Exception.Message }
    }
    Write-Host ""
    
    # Trust Discovery
    Write-Host "=== Trust Discovery (T1482) ===" -ForegroundColor Yellow
    try {
        $trustResults = Invoke-TrustDiscovery -Detailed:$Detailed
        $allResults += @{ Technique = "Trust Discovery"; Results = $trustResults; Count = $trustResults.Count }
        Write-Host "✓ Completed: Found $($trustResults.Count) trust entries" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Failed: $($_.Exception.Message)" -ForegroundColor Red
        $allResults += @{ Technique = "Trust Discovery"; Results = @(); Count = 0; Error = $_.Exception.Message }
    }
    Write-Host ""
    
    # Generate summary report
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    $summaryReport = @"
========================================
ACTIVE DIRECTORY RECONNAISSANCE SUMMARY
========================================

Execution Details:
- Start Time: $($startTime.ToString("yyyy-MM-dd HH:mm:ss UTC"))
- End Time: $($endTime.ToString("yyyy-MM-dd HH:mm:ss UTC"))  
- Duration: $($duration.ToString("mm\:ss"))
- Target Domain: $(if($global:ADReconConfig.Domain) { $global:ADReconConfig.Domain } else { 'Current Domain' })
- Output Location: $($global:ADReconConfig.OutputDirectory)

Reconnaissance Results:
$($allResults | ForEach-Object { 
    if ($_.Error) {
        "- $($_.Technique): FAILED ($($_.Error))"
    } else {
        "- $($_.Technique): $($_.Count) items discovered"
    }
} | Out-String)

MITRE ATT&CK Techniques Executed:
- T1087.002: Account Discovery - Domain Account
- T1615: Group Policy Discovery  
- T1018: Remote System Discovery
- T1482: Domain Trust Discovery

Total Items Discovered: $($allResults | Where-Object { -not $_.Error } | Measure-Object -Property Count -Sum | Select-Object -ExpandProperty Sum)

Files Generated:
$(Get-ChildItem -Path $global:ADReconConfig.OutputDirectory -Filter "$($global:ADReconConfig.Prefix)*" | ForEach-Object { "- $($_.Name)" } | Out-String)
"@
    
    $summaryFile = Join-Path $global:ADReconConfig.OutputDirectory "$($global:ADReconConfig.Prefix)ReconSummary.txt"
    $summaryReport | Out-File -FilePath $summaryFile -Encoding UTF8
    
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "  AD RECONNAISSANCE COMPLETE" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Green
    $allResults | Where-Object { -not $_.Error } | ForEach-Object {
        Write-Host "✓ $($_.Technique): $($_.Count) items" -ForegroundColor Green
    }
    $allResults | Where-Object { $_.Error } | ForEach-Object {
        Write-Host "✗ $($_.Technique): Failed" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Results saved to: $($global:ADReconConfig.OutputDirectory)" -ForegroundColor Cyan
    Write-Host "Summary report: $summaryFile" -ForegroundColor Cyan
    
    return $allResults
}

# Utility Functions
function Ensure-OutputDirectory {
    if (-not (Test-Path $global:ADReconConfig.OutputDirectory)) {
        try {
            New-Item -ItemType Directory -Path $global:ADReconConfig.OutputDirectory -Force | Out-Null
            Write-Host "✓ Created output directory: $($global:ADReconConfig.OutputDirectory)" -ForegroundColor Green
        }
        catch {
            Write-Error "Failed to create output directory: $($_.Exception.Message)"
        }
    }
}

function Get-ADReconResults {
    <#
    .SYNOPSIS
    Retrieves and displays reconnaissance results
    .DESCRIPTION
    Shows summary of reconnaissance results from output directory
    #>
    
    if (-not (Test-Path $global:ADReconConfig.OutputDirectory)) {
        Write-Host "No results found. Run Invoke-FullADReconnaissance first." -ForegroundColor Yellow
        return
    }
    
    $resultFiles = Get-ChildItem -Path $global:ADReconConfig.OutputDirectory -Filter "$($global:ADReconConfig.Prefix)*"
    
    if ($resultFiles.Count -eq 0) {
        Write-Host "[!] No AD reconnaissance results found." -ForegroundColor Yellow
        return
    }
    
    Write-Host "Active Directory Reconnaissance Results:" -ForegroundColor Cyan
    Write-Host "Location: $($global:ADReconConfig.OutputDirectory)" -ForegroundColor Gray
    Write-Host ""
    
    foreach ($file in $resultFiles) {
        $fileSize = [math]::Round($file.Length / 1KB, 2)
        Write-Host "- $($file.Name) ($fileSize KB)" -ForegroundColor White
        Write-Host "   Modified: $(Get-Date $file.LastWriteTime -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
        Write-Host ""
    }
}

function Set-ADReconConfig {
    <#
    .SYNOPSIS
    Configure AD reconnaissance settings
    .DESCRIPTION
    Sets target domain, server, and output preferences
    #>
    param(
        [string]$Domain,
        [string]$Server,
        [string]$OutputDirectory
    )
    
    if ($Domain) { 
        $global:ADReconConfig.Domain = $Domain 
        Write-Host "✓ Target domain set to: $Domain" -ForegroundColor Green
    }
    if ($Server) { 
        $global:ADReconConfig.Server = $Server 
        Write-Host "✓ Target server set to: $Server" -ForegroundColor Green
    }
    if ($OutputDirectory) { 
        $global:ADReconConfig.OutputDirectory = $OutputDirectory 
        Write-Host "✓ Output directory set to: $OutputDirectory" -ForegroundColor Green
    }
}

# Aliases for convenience
New-Alias -Name "Run-ADRecon" -Value "Invoke-FullADReconnaissance" -Force
New-Alias -Name "Get-ADResults" -Value "Get-ADReconResults" -Force

# Export functions
Export-ModuleMember -Function @(
    'Install-RSATTools',
    'Invoke-DomainUserDiscovery',
    'Invoke-GroupPolicyDiscovery', 
    'Invoke-ComputerDiscovery',
    'Invoke-TrustDiscovery',
    'Invoke-FullADReconnaissance',
    'Get-ADReconResults',
    'Set-ADReconConfig'
) -Alias @('Run-ADRecon', 'Get-ADResults')