<# 
.SYNOPSIS
  Collects host identity info (OS, hardware, network, user) using:
  - systeminfo / hostname (built-in)
  - Get-ComputerInfo
  - Get-CimInstance Win32_* (OperatingSystem, ComputerSystem, BIOS, Processor, Network)

.EXAMPLE
  .\Get-HostIdentity.ps1

.EXAMPLE
  .\Get-HostIdentity.ps1 -ComputerName PC01,PC02 -Credential (Get-Credential) | Export-Csv hosts.csv -NoTypeInformation

.EXAMPLE
  .\Get-HostIdentity.ps1 -ComputerName (Get-Content .\targets.txt) -JsonOut .\hosts.json
#>

[CmdletBinding()]
param(
  [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
  [Alias('CN','Name')]
  [string[]] $ComputerName = @('localhost'),

  [pscredential] $Credential,

  [string] $JsonOut,
  [string] $CsvOut,

  [switch] $VerboseSysInfoFallback   # Show extra details when falling back to systeminfo
)

begin {
  function Invoke-Safe {
    param([scriptblock]$Block)
    try { & $Block } catch { $null }
  }

  function Get-NetworkInfoCim {
    param($Computer, $Cred)
    $adapters = Invoke-Safe { 
      Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=TRUE" -ComputerName $Computer -Credential $Cred -ErrorAction Stop 
    }
    if (-not $adapters) { return [PSCustomObject]@{ IPs=@(); MACs=@(); DNSServers=@() } }
    [PSCustomObject]@{
      IPs        = $adapters.IPAddress      | Where-Object {$_} | Select-Object -Unique
      MACs       = $adapters.MACAddress     | Where-Object {$_} | Select-Object -Unique
      DNSServers = $adapters.DNSServerSearchOrder | Where-Object {$_} | Select-Object -Unique
    }
  }

  function Get-HostIdentity {
    param(
      [string] $Computer = 'localhost',
      [pscredential] $Cred
    )

    $isLocal = $Computer -in @('localhost','127.0.0.1','.',$env:COMPUTERNAME)

    # --- Preferred: CIM/WMI ---
    $os   = Invoke-Safe { Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName $Computer -Credential $Cred -ErrorAction Stop }
    $cs   = Invoke-Safe { Get-CimInstance -ClassName Win32_ComputerSystem  -ComputerName $Computer -Credential $Cred -ErrorAction Stop }
    $bios = Invoke-Safe { Get-CimInstance -ClassName Win32_BIOS            -ComputerName $Computer -Credential $Cred -ErrorAction Stop }
    $cpu  = Invoke-Safe { Get-CimInstance -ClassName Win32_Processor       -ComputerName $Computer -Credential $Cred -ErrorAction Stop }
    $net  = Get-NetworkInfoCim -Computer $Computer -Cred $Cred

    # Hostname + domain (prefer CIM, fall back to built-ins)
    $hostName = if ($cs.DNSHostName) { $cs.DNSHostName } elseif ($isLocal) { (Invoke-Safe { hostname }) } else { $null }
    $domain   = $cs.Domain
    $fqdn     = if ($hostName -and $cs.Domain) { "$hostName.$($cs.Domain)" } else { $hostName }

    # OS details (mix of CIM + Get-ComputerInfo if available)
    $gci = $null
    if ($isLocal) {
      $gci = Invoke-Safe { Get-ComputerInfo -ErrorAction Stop }
    }

    $obj = [PSCustomObject]@{
      QueriedAtUTC       = (Get-Date).ToUniversalTime()
      Target             = $Computer
      Reachable          = $null
      Hostname           = $hostName
      Domain             = $domain
      FQDN               = $fqdn

      OSName             = $os.Caption
      OSVersion          = $os.Version
      OSBuild            = $gci.OsBuildNumber
      InstallDate        = if ($os.InstallDate) { [Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate) }
      LastBootUpTime     = if ($os.LastBootUpTime) { [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime) }
      UptimeDays         = if ($os.LastBootUpTime) { 
                              [Math]::Round((New-TimeSpan -Start ([Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)) -End (Get-Date)).TotalDays,2)
                           }

      Manufacturer       = $cs.Manufacturer
      Model              = $cs.Model
      SerialNumber       = $bios.SerialNumber
      BIOSVersion        = ($bios.SMBIOSBIOSVersion, $bios.BIOSVersion -join ' ') -replace '\s+', ' '
      CPU                = ($cpu.Name | Select-Object -First 1)
      LogicalProcessors  = ($cpu.NumberOfLogicalProcessors | Measure-Object -Sum).Sum
      PhysicalCores      = ($cpu.NumberOfCores | Measure-Object -Sum).Sum
      RAM_GB             = if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory/1GB,2) }

      LoggedOnUser       = $cs.UserName
      IPAddresses        = $net.IPs -join ', '
      MACAddresses       = $net.MACs -join ', '
      DNSServers         = $net.DNSServers -join ', '

      Source_OS          = 'Get-CimInstance Win32_OperatingSystem'
      Source_System      = 'Get-CimInstance Win32_ComputerSystem'
      Source_BIOS        = 'Get-CimInstance Win32_BIOS'
      Source_Network     = 'Get-CimInstance Win32_NetworkAdapterConfiguration'
      Source_Extras      = if ($gci) { 'Get-ComputerInfo' } else { $null }
      FallbackUsed       = $false
      Notes              = $null
    }

    # Ping reachability check
    $obj.Reachable = !!(Invoke-Safe { Test-Connection -ComputerName $Computer -Count 1 -Quiet })

    # --- Fallbacks for minimal info (systeminfo/hostname) ---
    if (-not $os -and $isLocal) {
      $obj.FallbackUsed = $true
      $hn = Invoke-Safe { hostname }
      if ($hn) { $obj.Hostname = $hn; $obj.FQDN = $hn }

      $sys = Invoke-Safe { systeminfo }
      if ($sys) {
        if ($VerboseSysInfoFallback) { Write-Verbose "Using systeminfo fallback for $Computer" }
        # Simple key extraction from systeminfo's text output
        $kv = @{}
        foreach ($line in $sys) {
          if ($line -match '^\s*([^:]+):\s*(.+)$') {
            $kv[$matches[1].Trim()] = $matches[2].Trim()
          }
        }
        $obj.OSName         = $obj.OSName         ?? $kv['OS Name']
        $obj.OSVersion      = $obj.OSVersion      ?? ($kv['OS Version'] -split '\s+' | Select-Object -First 1)
        $obj.OSBuild        = $obj.OSBuild        ?? ($kv['OS Version'] -replace '.*Build\s+(\d+).*','$1')
        $obj.InstallDate    = $obj.InstallDate    ?? (Invoke-Safe { Get-Date $kv['Original Install Date'] })
        $obj.LastBootUpTime = $obj.LastBootUpTime ?? (Invoke-Safe { Get-Date $kv['System Boot Time'] })
        $obj.Manufacturer   = $obj.Manufacturer   ?? $kv['System Manufacturer']
        $obj.Model          = $obj.Model          ?? $kv['System Model']
        $obj.RAM_GB         = $obj.RAM_GB         ?? (Invoke-Safe {
                                  if ($kv['Total Physical Memory']) {
                                    [math]::Round(([double]($kv['Total Physical Memory'] -replace '[^\d.]'))/1MB,2)
                                  }
                                })
      }
      $obj.Notes = 'CIM unavailable; used systeminfo/hostname locally.'
    }

    return $obj
  }
}

process {
  $results = foreach ($cn in $ComputerName) {
    Get-HostIdentity -Computer $cn -Cred $Credential
  }

  if ($CsvOut) {
    $results | Export-Csv -Path $CsvOut -NoTypeInformation
    Write-Host "CSV written to $CsvOut"
  }
  if ($JsonOut) {
    $results | ConvertTo-Json -Depth 6 | Set-Content -Path $JsonOut -Encoding UTF8
    Write-Host "JSON written to $JsonOut"
  }

  $results
}


# Local machine (quick view)
# .\Get-HostIdentity.ps1 | Format-Table Hostname,OSName,OSVersion,Model,IPAddresses

# Multiple hosts with creds, export CSV
# .\Get-HostIdentity.ps1 -ComputerName PC01,PC02,SRV01 -Credential (Get-Credential) -CsvOut .\hosts.csv

# From a file, export JSON
# Get-Content .\targets.txt | .\Get-HostIdentity.ps1 -JsonOut .\hosts.json

