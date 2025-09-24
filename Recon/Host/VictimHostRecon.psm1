# Victim Host Reconnaissance PowerShell Module
# Security Research and Simulation Framework

# Module variables
$Global:ReconResults = @{}
$Global:ReconOutputPath = "C:\Intel\Logs"

# Ensure output directory exists
if (!(Test-Path $Global:ReconOutputPath)) {
    New-Item -ItemType Directory -Path $Global:ReconOutputPath -Force | Out-Null
}

Write-Host "[+] Victim Host Recon Module Loaded" -ForegroundColor Green
Write-Host "[+] Output Directory: $Global:ReconOutputPath" -ForegroundColor Yellow

#region Core Functions

function Invoke-AccountDiscovery {
    <#
    .SYNOPSIS
    Executes Account Discovery (T1087) reconnaissance
    
    .DESCRIPTION
    Discovers local and domain user accounts with focus on administrative privileges
    
    .PARAMETER ComputerName
    Target computers to scan
    
    .PARAMETER OutputFile
    Custom output file path
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName = @($env:COMPUTERNAME),
        [string]$OutputFile = "$Global:ReconOutputPath\VictimHost_AccountDiscovery.txt"
    )
    
    Write-Host "[*] Starting Account Discovery (T1087)..." -ForegroundColor Cyan
    
    try {
        $scriptPath = Join-Path $PSScriptRoot "Account Discovery (T1087).ps1"
        $results = & $scriptPath -ComputerName $ComputerName
        
        # Save results
        $results | Out-File -FilePath $OutputFile -Encoding UTF8
        $Global:ReconResults['AccountDiscovery'] = @{
            Results = $results
            OutputFile = $OutputFile
            Timestamp = Get-Date
        }
        
        Write-Host "[+] Account Discovery completed. Results saved to: $OutputFile" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Error "Account Discovery failed: $($_.Exception.Message)"
    }
}


function Invoke-NetworkServiceDiscovery {
    <#
    .SYNOPSIS
    Executes Network Service Discovery (T1046) reconnaissance
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFile = "$Global:ReconOutputPath\VictimHost_NetworkServiceDiscovery.txt"
    )
    
    Write-Host "[*] Starting Network Service Discovery (T1046)..." -ForegroundColor Cyan
    
    try {
        $scriptPath = Join-Path $PSScriptRoot "Network Service Discovery (T1046).ps1"
        $results = & $scriptPath
        
        $results | Out-File -FilePath $OutputFile -Encoding UTF8
        $Global:ReconResults['NetworkServiceDiscovery'] = @{
            Results = $results
            OutputFile = $OutputFile
            Timestamp = Get-Date
        }
        
        Write-Host "[+] Network Service Discovery completed. Results saved to: $OutputFile" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Error "Network Service Discovery failed: $($_.Exception.Message)"
    }
}

function Invoke-ProcessDiscovery {
    <#
    .SYNOPSIS
    Executes Process Discovery (T1057) reconnaissance
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFile = "$Global:ReconOutputPath\VictimHost_ProcessDiscovery.txt"
    )
    
    Write-Host "[*] Starting Process Discovery (T1057)..." -ForegroundColor Cyan
    
    try {
        $scriptPath = Join-Path $PSScriptRoot "Process Discovery (T1057).ps1"
        $results = & $scriptPath
        
        $results | Out-File -FilePath $OutputFile -Encoding UTF8
        $Global:ReconResults['ProcessDiscovery'] = @{
            Results = $results
            OutputFile = $OutputFile
            Timestamp = Get-Date
        }
        
        Write-Host "[+] Process Discovery completed. Results saved to: $OutputFile" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Error "Process Discovery failed: $($_.Exception.Message)"
    }
}

function Invoke-SoftwareDiscovery {
    <#
    .SYNOPSIS
    Executes Software Discovery (T1518) reconnaissance
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFile = "$Global:ReconOutputPath\VictimHost_SoftwareDiscovery.txt"
    )
    
    Write-Host "[*] Starting Software Discovery (T1518)..." -ForegroundColor Cyan
    
    try {
        $scriptPath = Join-Path $PSScriptRoot "Software Discovery (T1518).ps1"
        $results = & $scriptPath
        
        $results | Out-File -FilePath $OutputFile -Encoding UTF8
        $Global:ReconResults['SoftwareDiscovery'] = @{
            Results = $results
            OutputFile = $OutputFile
            Timestamp = Get-Date
        }
        
        Write-Host "[+] Software Discovery completed. Results saved to: $OutputFile" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Error "Software Discovery failed: $($_.Exception.Message)"
    }
}

function Invoke-SystemInfoDiscovery {
    <#
    .SYNOPSIS
    Executes System Information Discovery (T1082) reconnaissance
    #>
    [CmdletBinding()]
    param(
        [string]$OutputFile = "$Global:ReconOutputPath\VictimHost_SystemInfoDiscovery.txt"
    )
    
    Write-Host "[*] Starting System Information Discovery (T1082)..." -ForegroundColor Cyan
    
    try {
        $scriptPath = Join-Path $PSScriptRoot "System Information Discovery (T1082).ps1"
        $results = & $scriptPath
        
        $results | Out-File -FilePath $OutputFile -Encoding UTF8
        $Global:ReconResults['SystemInfoDiscovery'] = @{
            Results = $results
            OutputFile = $OutputFile
            Timestamp = Get-Date
        }
        
        Write-Host "[+] System Information Discovery completed. Results saved to: $OutputFile" -ForegroundColor Green
        return $results
    }
    catch {
        Write-Error "System Information Discovery failed: $($_.Exception.Message)"
    }
}

function Invoke-FullReconnaissance {
    <#
    .SYNOPSIS
    Executes all reconnaissance modules in sequence
    
    .DESCRIPTION
    Runs all MITRE ATT&CK discovery techniques in a logical order
    
    .PARAMETER ComputerName
    Target computers for applicable scans
    
    .PARAMETER Delay
    Delay between each module execution (seconds)
    #>
    [CmdletBinding()]
    param(
        [string[]]$ComputerName = @($env:COMPUTERNAME),
        [int]$Delay = 5
    )
    
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host " VICTIM HOST - FULL RECONNAISSANCE" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    Write-Host "Target: $($ComputerName -join ', ')" -ForegroundColor Yellow
    Write-Host "Output Directory: $Global:ReconOutputPath" -ForegroundColor Yellow
    Write-Host ""
    
    $modules = @(
        { Invoke-SystemInfoDiscovery },
        { Invoke-AccountDiscovery -ComputerName $ComputerName },
        { Invoke-ProcessDiscovery },
        { Invoke-SoftwareDiscovery },
        { Invoke-NetworkServiceDiscovery }
    )
    
    $totalModules = $modules.Count
    $currentModule = 0
    
    foreach ($module in $modules) {
        $currentModule++
        Write-Host "[*] Module $currentModule/$totalModules" -ForegroundColor Yellow
        
        try {
            & $module
        }
        catch {
            Write-Warning "Module failed: $($_.Exception.Message)"
        }
        
        if ($currentModule -lt $totalModules) {
            Write-Host "[*] Waiting $Delay seconds before next module..." -ForegroundColor Gray
            Start-Sleep -Seconds $Delay
        }
    }
    
    Write-Host ""
    Write-Host "[+] Full reconnaissance completed!" -ForegroundColor Green
    Write-Host "[+] Results available in: $Global:ReconOutputPath" -ForegroundColor Green
    
    # Create summary report
    $summaryPath = "$Global:ReconOutputPath\VictimHost_ReconSummary.txt"
    $summary = @"
VICTIM HOST RECONNAISSANCE SUMMARY
Generated: $(Get-Date)
Target: $($ComputerName -join ', ')
Output Directory: $Global:ReconOutputPath

MODULES EXECUTED:
- System Information Discovery (T1082)
- Account Discovery (T1087)
- Process Discovery (T1057)
- Software Discovery (T1518)
- Network Service Discovery (T1046)

RESULTS:
$($Global:ReconResults.Keys | ForEach-Object { "- $_`: $($Global:ReconResults[$_].OutputFile)" } | Out-String)
"@
    
    $summary | Out-File -FilePath $summaryPath -Encoding UTF8
    Write-Host "[+] Summary report: $summaryPath" -ForegroundColor Green
}

function Get-ReconResults {
    <#
    .SYNOPSIS
    Retrieves stored reconnaissance results
    #>
    [CmdletBinding()]
    param()
    
    if ($Global:ReconResults.Count -eq 0) {
        Write-Warning "No reconnaissance results available. Run Invoke-FullReconnaissance first."
        return
    }
    
    Write-Host "Available Results:" -ForegroundColor Green
    $Global:ReconResults.Keys | ForEach-Object {
        $result = $Global:ReconResults[$_]
        Write-Host "- $_`: $($result.OutputFile) ($(Get-Date $result.Timestamp -Format 'yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Yellow
    }
    
    Write-Host "`nOutput Directory: $Global:ReconOutputPath" -ForegroundColor Cyan
    return $Global:ReconResults
}

#endregion

#region Aliases
Set-Alias -Name "Run-Recon" -Value "Invoke-FullReconnaissance"
Set-Alias -Name "Get-HostInfo" -Value "Invoke-SystemInfoDiscovery"  
Set-Alias -Name "Start-Discovery" -Value "Invoke-FullReconnaissance"
#endregion

# Export module functions
Export-ModuleMember -Function @(
    'Invoke-AccountDiscovery',
    'Invoke-NetworkServiceDiscovery',
    'Invoke-ProcessDiscovery',
    'Invoke-SoftwareDiscovery',
    'Invoke-SystemInfoDiscovery',
    'Invoke-FullReconnaissance',
    'Get-ReconResults'
) -Alias @(
    'Run-Recon',
    'Get-HostInfo',
    'Start-Discovery'
)