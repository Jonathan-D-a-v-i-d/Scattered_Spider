<#
.SYNOPSIS
  Network services survey: local connections, domain hosts, open TCP ports (probe), SMB shares, and host relationship edges.

.EXAMPLE
  .\Get-NetworkSurvey.ps1

.EXAMPLE
  .\Get-NetworkSurvey.ps1 -ProbeCommonPorts -OutCsv .\survey.csv

.EXAMPLE
  .\Get-NetworkSurvey.ps1 -TargetsFile .\hosts.txt -ProbeCommonPorts -TimeoutMs 800 -JsonOut .\survey.json
#>

[CmdletBinding()]
param(
  # Optional: seed list of hosts to probe (names or IPs). If omitted, will try domain discovery.
  [string[]] $ComputerName,

  # Read additional targets from file (one per line)
  [string] $TargetsFile,

  # Probe common TCP ports on each host (non-intrusive TCP connect checks)
  [switch] $ProbeCommonPorts,

  # Milliseconds to wait per port probe
  [int] $TimeoutMs = 700,

  # Parallel jobs for port probes (be kind to the network)
  [int] $MaxConcurrency = 25,

  # Output files
  [string] $OutCsv,
  [string] $JsonOut
)

begin {
  Write-Verbose "Starting Network Survey..."

  # Common enterprise ports (edit to taste)
  $CommonTcpPorts =  @(22, 25, 53, 80, 88, 110, 135, 139, 143, 389, 443, 445, 587, 593, 636, 1433, 1521, 3306, 3389, 4444, 5432, 5985, 5986, 8022, 8443)

  function Invoke-Safe { param([scriptblock]$Block) try { & $Block } catch { $null } }

  function Get-LocalConnections {
    # Prefer Get-NetTCPConnection; fall back to netstat for broad coverage
    $tcp = Invoke-Safe { Get-NetTCPConnection -ErrorAction Stop }
    if ($tcp) {
      $procById = @(Get-Process) | Group-Object Id -AsHashTable -AsString
      return $tcp | ForEach-Object {
        $pid = $_.OwningProcess
        $p   = $procById["$pid"]
        [PSCustomObject]@{
          Source         = 'Get-NetTCPConnection'
          LocalAddress   = $_.LocalAddress
          LocalPort      = $_.LocalPort
          RemoteAddress  = $_.RemoteAddress
          RemotePort     = $_.RemotePort
          State          = $_.State
          PID            = $pid
          ProcessName    = $p.Name
        }
      }
    }

    # netstat -ano parsing
    $lines = Invoke-Safe { netstat -ano -p tcp }
    if (-not $lines) { return @() }
    $data = foreach ($ln in $lines) {
      if ($ln -match '^\s*TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)\s*$') {
        $localAddr,$localPort,$remoteAddr,$remotePort,$state,$pid = $matches[1..6]
        $pname = (Invoke-Safe { (Get-Process -Id $pid -ErrorAction Stop).Name })
        [PSCustomObject]@{
          Source         = 'netstat'
          LocalAddress   = $localAddr
          LocalPort      = [int]$localPort
          RemoteAddress  = $remoteAddr
          RemotePort     = [int]$remotePort
          State          = $state
          PID            = [int]$pid
          ProcessName    = $pname
        }
      }
    }
    $data
  }

  function Get-DomainHosts {
    $hosts = New-Object System.Collections.Generic.HashSet[string]

    # net view /domain → list domains, then expand each domain
    $domainsRaw = Invoke-Safe { (net view /domain) 2>$null }
    $domains = @()
    if ($domainsRaw) {
      $domains = $domainsRaw |
        Where-Object { $_ -match '^\s{2,}([^\s].+)$' } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ -notmatch '^\*' } |
        Select-Object -Unique
    }
    if (-not $domains) { $domains = @( $env:USERDNSDOMAIN ) | Where-Object { $_ } }

    foreach ($dom in $domains) {
      $rows = Invoke-Safe { (net view /domain:$dom) 2>$null }
      if ($rows) {
        foreach ($r in $rows) {
          if ($r -match '^\\\\([^\s\\]+)') { [void]$hosts.Add($matches[1]) }
        }
      }
    }

    # Enrich via AD if available
    $adHosts = Invoke-Safe {
      if (Get-Module -ListAvailable -Name ActiveDirectory) {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        Get-ADComputer -Filter * -Properties DNSHostName |
          Select-Object -ExpandProperty DNSHostName |
          Where-Object { $_ } |
          Select-Object -Unique
      }
    }
    if ($adHosts) { $adHosts | ForEach-Object { [void]$hosts.Add($_) } }

    $hosts
  }

  function Get-HostShares {
    param([string] $Host)
    $rows = Invoke-Safe { (net view "\\$Host") 2>$null }
    if (-not $rows) { return @() }
    $shares = foreach ($line in $rows) {
      # Typical "ShareName   Type   Remark" lines
      if ($line -match '^\s*([^\s]+)\s+(Disk|Print|IPC)\b') {
        [PSCustomObject]@{
          Host  = $Host
          Share = $matches[1]
          Type  = $matches[2]
        }
      }
    }
    $shares
  }

  function Test-TcpPort {
    param(
      [string] $Host,
      [int]    $Port,
      [int]    $Timeout = 700
    )
    $result = [PSCustomObject]@{
      Host         = $Host
      Port         = $Port
      TcpOpen      = $false
      LatencyMs    = $null
      SvcGuess     = $null
      Error        = $null
    }
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      $tnc = Test-NetConnection -ComputerName $Host -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction Stop
      $result.TcpOpen = [bool]$tnc
      $sw.Stop()
      $result.LatencyMs = [int]$sw.ElapsedMilliseconds
    } catch {
      $sw.Stop()
      $result.Error = $_.Exception.Message
    }
    # Light service guess (very rough)
    $wellKnown = @{
      22='SSH';25='SMTP';53='DNS';80='HTTP';88='Kerberos';110='POP3';135='RPC';139='SMB(139)'
      143='IMAP';389='LDAP';443='HTTPS';445='SMB';587='SMTP-Submit';593='RPC/EPM';636='LDAPS'
      1433='MSSQL';1521='Oracle';3306='MySQL';3389='RDP';4444='Custom';5432='Postgres'
      5985='WinRM-HTTP';5986='WinRM-HTTPS';8022='SSH-Alt';8443='HTTPS-Alt'
    }
    $result.SvcGuess = $wellKnown[[string]$Port]
    $result
  }

  function Resolve-NameSafe {
    param([string] $NameOrIp)
    $dns = Invoke-Safe { Resolve-DnsName -Name $NameOrIp -ErrorAction Stop }
    if ($dns) {
      $a = $dns | Where-Object {$_.Type -in 'A','AAAA'} | Select-Object -First 1
      $ptr = $dns | Where-Object {$_.Type -eq 'PTR'} | Select-Object -First 1
      return [PSCustomObject]@{
        Query     = $NameOrIp
        Address   = $a.IPAddress
        PTR       = $ptr.NameHost
      }
    }
    [PSCustomObject]@{ Query=$NameOrIp; Address=$null; PTR=$null }
  }
}

process {
  # 1) Local live connections + process/service mapping
  $localConns = Get-LocalConnections

  # Try to attach services to PIDs (best effort)
  $svcTable = Invoke-Safe { Get-CimInstance Win32_Service } | Group-Object ProcessId -AsHashTable -AsString
  $localDetailed = $localConns | ForEach-Object {
    $svc = if ($_.PID -and $svcTable) { $svcTable["$($_.PID)"] }
    [PSCustomObject]@{
      Section        = 'LocalConnection'
      LocalAddress   = $_.LocalAddress
      LocalPort      = $_.LocalPort
      RemoteAddress  = $_.RemoteAddress
      RemotePort     = $_.RemotePort
      State          = $_.State
      PID            = $_.PID
      ProcessName    = $_.ProcessName
      ServiceNames   = ($svc | ForEach-Object { $_.Name }) -join ', '
    }
  }

  # 2) Build host relationship edges from established connections
  $edges = $localConns | Where-Object { $_.State -eq 'Established' -and $_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0' } |
    ForEach-Object {
      [PSCustomObject]@{
        Section        = 'Edge'
        FromHost       = $env:COMPUTERNAME
        FromIP         = $_.LocalAddress
        FromPort       = $_.LocalPort
        To             = $_.RemoteAddress
        ToPort         = $_.RemotePort
        ByProcess      = $_.ProcessName
        PID            = $_.PID
      }
    }

  # 3) Discover hosts
  $targets = New-Object System.Collections.Generic.HashSet[string]
  if ($ComputerName)       { $ComputerName       | Where-Object {$_} | ForEach-Object { [void]$targets.Add($_) } }
  if (Test-Path $TargetsFile) { Get-Content $TargetsFile | Where-Object {$_} | ForEach-Object { [void]$targets.Add($_) } }

  if ($targets.Count -eq 0) {
    $discovered = Get-DomainHosts
    if ($discovered) { $discovered | ForEach-Object { [void]$targets.Add($_) } }
  }

  # 4) Per-host resolution + SMB shares + optional port probes
  $hostRows = [System.Collections.Generic.List[object]]::new()
  foreach ($t in $targets) {
    $res = Resolve-NameSafe -NameOrIp $t
    $shares = Get-HostShares -Host $t

    if ($shares) {
      foreach ($s in $shares) {
        $hostRows.Add([PSCustomObject]@{
          Section  = 'SMBShare'
          Host     = $t
          Address  = $res.Address
          PTR      = $res.PTR
          Share    = $s.Share
          Type     = $s.Type
        })
      }
    } else {
      $hostRows.Add([PSCustomObject]@{
        Section  = 'Host'
        Host     = $t
        Address  = $res.Address
        PTR      = $res.PTR
      })
    }

    if ($ProbeCommonPorts) {
      # Queue limited parallel port probes per host
      $sem = New-Object System.Threading.SemaphoreSlim($MaxConcurrency,$MaxConcurrency)
      $tasks = foreach ($p in $CommonTcpPorts) {
        $null = $sem.Wait()
        [System.Threading.Tasks.Task]::Run({
          try { Test-TcpPort -Host $t -Port $p -Timeout $using:TimeoutMs }
          finally { $using:sem.Release() | Out-Null }
        })
      }
      [System.Threading.Tasks.Task]::WaitAll($tasks)
      $results = $tasks | ForEach-Object { $_.Result } | Where-Object { $_ }
      foreach ($r in $results) {
        $hostRows.Add([PSCustomObject]@{
          Section    = 'PortProbe'
          Host       = $r.Host
          Port       = $r.Port
          TcpOpen    = $r.TcpOpen
          LatencyMs  = $r.LatencyMs
          SvcGuess   = $r.SvcGuess
          Error      = $r.Error
        })
      }
    }
  }

  # Collate output
  $output = @()
  $output += $localDetailed
  $output += $edges
  $output += $hostRows

  if ($OutCsv) {
    $output | Export-Csv -Path $OutCsv -NoTypeInformation
    Write-Host "CSV written: $OutCsv"
  }
  if ($JsonOut) {
    $output | ConvertTo-Json -Depth 6 | Set-Content -Path $JsonOut -Encoding UTF8
    Write-Host "JSON written: $JsonOut"
  }

  $output
}



# 1) Fast local snapshot + discovered hosts (no port probing)
# .\Get-NetworkSurvey.ps1 | Format-Table -Auto

# 2) Include TCP port probing (be considerate on big networks)
# .\Get-NetworkSurvey.ps1 -ProbeCommonPorts -MaxConcurrency 20 -OutCsv .\survey.csv

# 3) Target a known list and export JSON
# .\Get-NetworkSurvey.ps1 -TargetsFile .\hosts.txt -ProbeCommonPorts -TimeoutMs 800 -JsonOut .\survey.json

