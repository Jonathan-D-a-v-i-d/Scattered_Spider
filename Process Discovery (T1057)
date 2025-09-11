<#
.SYNOPSIS
  Enumerate running processes on local or remote hosts.

.DESCRIPTION
  - Uses Get-Process for rich local/remote info.
  - Falls back to tasklist /svc and wmic process get if needed.
  - Returns objects with PID, process name, executable path, and optionally services tied to that PID.
  - Helpful for spotting security tools, RMM agents, or unusual applications.

.EXAMPLES
  .\Get-RunningProcesses.ps1
  .\Get-RunningProcesses.ps1 -ComputerName PC01,SRV01 -Credential (Get-Credential) | 
    Where-Object { $_.Name -match 'anydesk|teamviewer|sentinel|defender' }
#>

[CmdletBinding()]
param(
  [string[]] $ComputerName = @('localhost'),
  [pscredential] $Credential,
  [string] $CsvOut,
  [string] $JsonOut
)

begin {
  function Invoke-Safe { param([scriptblock]$Block) try { & $Block } catch { $null } }

  function Get-ProcessInfo {
    param([string]$Computer = 'localhost', [pscredential]$Cred)

    $isLocal = $Computer -in @('localhost','127.0.0.1',$env:COMPUTERNAME,'.')

    # --- Try Get-Process first ---
    $procs = Invoke-Safe {
      if ($isLocal) { Get-Process -IncludeUserName -ErrorAction Stop }
      else { Get-Process -ComputerName $Computer -ErrorAction Stop }
    }

    if ($procs) {
      return $procs | ForEach-Object {
        [PSCustomObject]@{
          Section        = 'Process'
          Host           = $Computer
          PID            = $_.Id
          Name           = $_.ProcessName
          Path           = $_.Path
          CPU            = $_.CPU
          WS_MB          = [math]::Round($_.WS / 1MB,2)
          UserName       = $_.UserName
          Source         = 'Get-Process'
        }
      }
    }

    # --- Fallback: tasklist /svc (local only, or remote with /s switch) ---
    $tasklist = if ($isLocal) {
      Invoke-Safe { tasklist /svc /fo csv /nh }
    } else {
      Invoke-Safe { tasklist /s $Computer /u $Cred.UserName /p $Cred.GetNetworkCredential().Password /svc /fo csv /nh }
    }

    if ($tasklist) {
      return $tasklist | ConvertFrom-Csv | ForEach-Object {
        [PSCustomObject]@{
          Section   = 'Process'
          Host      = $Computer
          PID       = [int]$_.PID
          Name      = $_.'Image Name'
          Path      = $null
          CPU       = $null
          WS_MB     = $null
          UserName  = $null
          Services  = $_.'Services'
          Source    = 'tasklist /svc'
        }
      }
    }

    # --- Fallback: WMIC (deprecated but still present on many hosts) ---
    $wmic = Invoke-Safe {
      wmic /node:$Computer process get ProcessId,Name,ExecutablePath /format:csv
    }
    if ($wmic) {
      return $wmic | ConvertFrom-Csv | Where-Object { $_.Name } | ForEach-Object {
        [PSCustomObject]@{
          Section  = 'Process'
          Host     = $_.Node
          PID      = [int]$_.ProcessId
          Name     = $_.Name
          Path     = $_.ExecutablePath
          Source   = 'wmic process get'
        }
      }
    }

    # Nothing succeeded
    return @([PSCustomObject]@{
      Section='Process'; Host=$Computer; PID=$null; Name=$null; Path=$null; Source='None'; Notes='Unable to enumerate'
    })
  }
}

process {
  $results = foreach ($cn in $ComputerName) {
    Get-ProcessInfo -Computer $cn -Cred $Credential
  }

  if ($CsvOut) {
    $results | Export-Csv -Path $CsvOut -NoTypeInformation
    Write-Host "CSV written: $CsvOut"
  }
  if ($JsonOut) {
    $results | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOut -Encoding UTF8
    Write-Host "JSON written: $JsonOut"
  }

  $results
}


# Local snapshot
# .\Get-RunningProcesses.ps1 | Format-Table -Auto

# Remote host with creds
# .\Get-RunningProcesses.ps1 -ComputerName SRV01 -Credential (Get-Credential)

# Export CSV for multiple servers
# .\Get-RunningProcesses.ps1 -ComputerName (Get-Content .\servers.txt) -CsvOut procs.csv

# Look for RMM tools or AV software
# .\Get-RunningProcesses.ps1 | Where-Object { $_.Name -match 'anydesk|teamviewer|kaseya|sentinel|cortex|defender' } | Format-Table
