<#
.SYNOPSIS
  Inventory installed software and detect security/RMM products across Windows hosts.

.DESCRIPTION
  - Reads HKLM/HKCU Uninstall keys (x64 & Wow6432Node).
  - Optionally queries WMIC product (slow; can trigger MSI self-repair).
  - Inspects Windows services and common install paths to detect EDR/AV/RMM.
  - Supports local or remote targets. Remote paths tried in order:
      1) Remote Registry (.NET) if the RemoteRegistry service is running and accessible
      2) Invoke-Command (WinRM) if available
      3) Optional WMIC fallback (if -UseWmic is supplied)

.PARAMETER ComputerName
  Hosts to scan. Defaults to localhost.

.PARAMETER Credential
  Credential for remote access (Remote Registry / WinRM / WMIC).

.PARAMETER UseWmic
  Include slow WMIC product enumeration as a last resort.

.PARAMETER CsvOut
  Export a flat CSV of software rows.

.PARAMETER JsonOut
  Export JSON including both Software and SecurityDetections.

.EXAMPLES
  .\Get-InstalledSoftware.ps1
  .\Get-InstalledSoftware.ps1 -ComputerName PC01,SRV01 -Credential (Get-Credential) -CsvOut sw.csv
  .\Get-InstalledSoftware.ps1 -ComputerName (Get-Content .\hosts.txt) -UseWmic -JsonOut inventory.json
#>

[CmdletBinding()]
param(
  [string[]] $ComputerName = @('localhost'),
  [pscredential] $Credential,
  [switch] $UseWmic,
  [string] $CsvOut,
  [string] $JsonOut
)

begin {
  function Invoke-Safe { param([scriptblock]$Block) try { & $Block } catch { $null } }

  # --- Known product indicators (names, services, files) --------------------
  $SecurityIndicators = @(
    # EDR / AV
    @{ NameRe='(?i)crowd.?strike|falcon';      SvcRe='(?i)CSAgent|falcond';        Paths=@('C:\Program Files\CrowdStrike') },
    @{ NameRe='(?i)sentinel.?one';             SvcRe='(?i)SentinelAgent';          Paths=@('C:\Program Files\SentinelOne') },
    @{ NameRe='(?i)cortex.?xdr|traps';         SvcRe='(?i)cyserver|cyverasvc';     Paths=@('C:\Program Files\Palo Alto Networks') },
    @{ NameRe='(?i)carbon black|cb defense';   SvcRe='(?i)CbDefense|CbAgent';      Paths=@('C:\Program Files\Carbon Black') },
    @{ NameRe='(?i)ms defender|microsoft defender|endpoint protection|security center';
                                             SvcRe='(?i)WinDefend|Sense';          Paths=@('C:\ProgramData\Microsoft\Windows Defender') },
    @{ NameRe='(?i)symantec|broadcom endpoint';SvcRe='(?i)SepMasterService|smc';    Paths=@('C:\Program Files\Symantec') },
    @{ NameRe='(?i)mcafee';                    SvcRe='(?i)mcshield|macmnsvc';      Paths=@('C:\Program Files\McAfee') },
    @{ NameRe='(?i)trend micro|worry-free';    SvcRe='(?i)ntrtscan|tmbmsrv';       Paths=@('C:\Program Files\Trend Micro') },
    @{ NameRe='(?i)sophos';                    SvcRe='(?i)sophos.*service';        Paths=@('C:\Program Files\Sophos') },
    @{ NameRe='(?i)bitdefender';               SvcRe='(?i)vsserv';                  Paths=@('C:\Program Files\Bitdefender') },
    @{ NameRe='(?i)eset';                      SvcRe='(?i)ekrn';                    Paths=@('C:\Program Files\ESET') },
    # RMM / Remote access
    @{ NameRe='(?i)anydesk';                   SvcRe='(?i)AnyDesk';                 Paths=@('C:\Program Files\AnyDesk') },
    @{ NameRe='(?i)teamviewer';                SvcRe='(?i)TeamViewer';              Paths=@('C:\Program Files\TeamViewer') },
    @{ NameRe='(?i)connectwise control|screenconnect';
                                             SvcRe='(?i)ScreenConnect';            Paths=@('C:\Program Files\ScreenConnect Client') },
    @{ NameRe='(?i)kaseya';                    SvcRe='(?i)Kaseya.*Agent';          Paths=@('C:\Program Files\Kaseya') },
    @{ NameRe='(?i)N-able|SolarWinds Take Control|RMM Agent';
                                             SvcRe='(?i)AdvancedMonitoringAgent';  Paths=@('C:\Program Files\N-able') },
    @{ NameRe='(?i)splashtop';                 SvcRe='(?i)SplashtopRemoteService'; Paths=@('C:\Program Files\Splashtop') },
    @{ NameRe='(?i)GoToAssist|LogMeIn|Rescue'; SvcRe='(?i)LMIGuardianSvc|LogMeIn'; Paths=@('C:\Program Files\LogMeIn') },
    @{ NameRe='(?i)RustDesk';                  SvcRe='(?i)rustdesk';                Paths=@('C:\Program Files\RustDesk') }
  )

  # Registry locations to check
  $RegUninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
  )

  # --- Local: read uninstall keys via PowerShell registry provider ----------
  function Get-LocalUninstallRows {
    foreach ($root in $RegUninstallRoots) {
      if (Test-Path $root) {
        Get-ChildItem $root -ErrorAction SilentlyContinue | ForEach-Object {
          $p = Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue
          if ($p -and $p.DisplayName) {
            [PSCustomObject]@{
              Host            = $env:COMPUTERNAME
              Hive            = ($root -split ':')[0]
              Key             = $_.PSChildName
              DisplayName     = $p.DisplayName
              DisplayVersion  = $p.DisplayVersion
              Publisher       = $p.Publisher
              InstallDate     = $p.InstallDate
              InstallLocation = $p.InstallLocation
              UninstallString = $p.UninstallString
              QuietUninstall  = $p.QuietUninstallString
              SystemComponent = $p.SystemComponent
              WindowsInstaller= $p.WindowsInstaller
              Source          = 'Registry'
            }
          }
        }
      }
    }
  }

  # --- Remote Registry via .NET (no PS Remoting required) -------------------
  function Get-RemoteUninstallRows {
    param([string]$Computer, [pscredential]$Cred)

    $rows = New-Object System.Collections.Generic.List[object]
    try {
      $imp = $null
      if ($Cred) {
        $imp = New-Object System.Management.Automation.PSCredential($Cred.UserName,$Cred.Password)
      }
      # Helper to open and read a hive/path remotely
      function Get-RemoteKeyValues {
        param([string]$HiveName,[string]$SubPath)
        $hiveEnum = [Microsoft.Win32.RegistryHive]::$HiveName
        $view64 = [Microsoft.Win32.RegistryView]::Registry64
        $view32 = [Microsoft.Win32.RegistryView]::Registry32
        foreach ($view in @($view64,$view32)) {
          try {
            $base = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($hiveEnum,$Computer,$view)
            $key  = $base.OpenSubKey($SubPath)
            if ($null -ne $key) {
              foreach ($sub in $key.GetSubKeyNames()) {
                $sk = $key.OpenSubKey($sub)
                if ($null -ne $sk) {
                  $dn = $sk.GetValue('DisplayName')
                  if ($dn) {
                    [PSCustomObject]@{
                      Host            = $Computer
                      Hive            = $HiveName
                      Key             = $sub
                      DisplayName     = $dn
                      DisplayVersion  = $sk.GetValue('DisplayVersion')
                      Publisher       = $sk.GetValue('Publisher')
                      InstallDate     = $sk.GetValue('InstallDate')
                      InstallLocation = $sk.GetValue('InstallLocation')
                      UninstallString = $sk.GetValue('UninstallString')
                      QuietUninstall  = $sk.GetValue('QuietUninstallString')
                      SystemComponent = $sk.GetValue('SystemComponent')
                      WindowsInstaller= $sk.GetValue('WindowsInstaller')
                      Source          = 'Registry(Remote)'
                    }
                  }
                }
              }
            }
          } catch {}
        }
      }

      $paths = @(
        @{Hive='LocalMachine'; Sub='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'},
        @{Hive='LocalMachine'; Sub='SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'},
        @{Hive='CurrentUser' ; Sub='SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'},
        @{Hive='CurrentUser' ; Sub='SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'}
      )
      foreach ($p in $paths) {
        $rows.AddRange( (Get-RemoteKeyValues -HiveName $p.Hive -SubPath $p.Sub) )
      }
    } catch {}
    $rows
  }

  # --- Optional WMIC --------------------------------------------------------
  function Get-WmicProducts {
    param([string]$Computer='localhost', [pscredential]$Cred)
    $cmd = if ($Computer -ieq 'localhost' -or $Computer -ieq $env:COMPUTERNAME) {
      'wmic product get Name,Version,Vendor /format:csv'
    } else {
      "wmic /node:$Computer product get Name,Version,Vendor /format:csv"
    }
    $envUser = $null
    $envPass = $null
    if ($Cred -and $Computer -notin @('localhost',$env:COMPUTERNAME)) {
      $envUser = $Cred.UserName
      $envPass = $Cred.GetNetworkCredential().Password
      $cmd = "wmic /user:$envUser /password:$envPass /node:$Computer product get Name,Version,Vendor /format:csv"
    }
    $raw = Invoke-Safe { cmd.exe /c $cmd }
    if (-not $raw) { return @() }
    $csv = $raw | ConvertFrom-Csv | Where-Object { $_.Name }
    $csv | ForEach-Object {
      [PSCustomObject]@{
        Host            = $_.Node
        Hive            = 'WMIC'
        Key             = $null
        DisplayName     = $_.Name
        DisplayVersion  = $_.Version
        Publisher       = $_.Vendor
        InstallDate     = $null
        InstallLocation = $null
        UninstallString = $null
        QuietUninstall  = $null
        SystemComponent = $null
        WindowsInstaller= $true
        Source          = 'WMIC product'
      }
    }
  }

  # --- Services & file-path checks for detections ---------------------------
  function Get-HostServices {
    param([string]$Computer='localhost', [pscredential]$Cred)
    $svc = Invoke-Safe {
      Get-CimInstance -ClassName Win32_Service -ComputerName $Computer -Credential $Cred -ErrorAction Stop
    }
    if ($svc) { return $svc }
    # Fallback via sc.exe (minimal)
    $raw = Invoke-Safe {
      if ($Computer -in @('localhost',$env:COMPUTERNAME)) { sc.exe query type= service state= all }
      else { sc.exe \\$Computer query type= service state= all }
    }
    if (-not $raw) { return @() }
    # Very light parse of SERVICE_NAME lines
    $names = $raw | Where-Object { $_ -match '^\s*SERVICE_NAME:\s*(.+)$' } | ForEach-Object { $matches[1].Trim() }
    $names | ForEach-Object {
      [PSCustomObject]@{ Name=$_; DisplayName=$_; State=$null; PathName=$null }
    }
  }

  function Test-HostPaths {
    param([string]$Computer='localhost',[string[]]$Paths)
    if ($Computer -in @('localhost',$env:COMPUTERNAME)) {
      return $Paths | ForEach-Object { [PSCustomObject]@{ Path=$_; Exists=(Test-Path $_) } }
    }
    # Remote path existence check via admin share (best effort)
    $results = @()
    foreach ($p in $Paths) {
      $drive = ($p -split ':')[0]
      $rest  = ($p -split ':')[1].TrimStart('\')
      $unc   = "\\$Computer\$drive`$\$rest"
      $exists = Test-Path $unc
      $results += [PSCustomObject]@{ Path=$p; Exists=$exists }
    }
    $results
  }

  function Detect-SecurityProducts {
    param(
      [string]$Computer='localhost',
      [object[]]$SoftwareRows,
      [object[]]$Services
    )
    $hits = New-Object System.Collections.Generic.List[object]
    foreach ($ind in $SecurityIndicators) {
      $nameHit = $SoftwareRows | Where-Object { $_.DisplayName -match $ind.NameRe }
      $svcHit  = $Services     | Where-Object { $_.Name        -match $ind.SvcRe -or $_.DisplayName -match $ind.SvcRe }
      $pathHit = Test-HostPaths -Computer $Computer -Paths $ind.Paths

      $evidence = @()
      if ($nameHit) { $evidence += "DisplayName match" }
      if ($svcHit)  { $evidence += "Service match" }
      if ($pathHit | Where-Object Exists) { $evidence += "Path exists" }

      if ($evidence.Count -gt 0) {
        $hits.Add([PSCustomObject]@{
          Host        = $Computer
          Indicator   = $ind.NameRe
          ServiceRe   = $ind.SvcRe
          Paths       = ($ind.Paths -join '; ')
          NameMatches = ($nameHit.DisplayName | Select-Object -Unique) -join '; '
          ServiceMatches = ($svcHit.Name | Select-Object -Unique) -join '; '
          PathExists  = (($pathHit | Where-Object Exists).Path -join '; ')
          Evidence    = ($evidence -join ', ')
          Section     = 'SecurityDetection'
        }) | Out-Null
      }
    }
    $hits
  }

  function Dedup-SoftwareRows {
    param([object[]]$Rows)
    $Rows | Group-Object { ($_.DisplayName, $_.DisplayVersion -join '||').ToLower() } |
      ForEach-Object { $_.Group | Select-Object -First 1 }
  }
}

process {
  $allSoftware = New-Object System.Collections.Generic.List[object]
  $allDetections = New-Object System.Collections.Generic.List[object]

  foreach ($cn in $ComputerName) {
    $isLocal = $cn -in @('localhost','.',$env:COMPUTERNAME,'127.0.0.1')

    # 1) Software rows via registry
    $rows = if ($isLocal) {
      Get-LocalUninstallRows
    } else {
      $r = Get-RemoteUninstallRows -Computer $cn -Cred $Credential
      if (-not $r -or $r.Count -eq 0) {
        # Try WinRM as fallback: run the local registry reader remotely
        $script = ${function:Get-LocalUninstallRows}.ToString()
        $sessRows = Invoke-Safe {
          Invoke-Command -ComputerName $cn -Credential $Credential -ScriptBlock ([ScriptBlock]::Create($script + "`nGet-LocalUninstallRows"))
        }
        $r = $sessRows
      }
      $r
    }

    # 2) Optional WMIC supplement
    if ($UseWmic) {
      $wm = Get-WmicProducts -Computer $cn -Cred $Credential
      if ($wm) { $rows += $wm }
    }

    $rows = Dedup-SoftwareRows -Rows $rows
    foreach ($row in $rows) { $allSoftware.Add($row) | Out-Null }

    # 3) Services & security detections
    $svcs = Get-HostServices -Computer $cn -Cred $Credential
    $hits = Detect-SecurityProducts -Computer $cn -SoftwareRows $rows -Services $svcs
    foreach ($h in $hits) { $allDetections.Add($h) | Out-Null }
  }

  # Exports
  if ($CsvOut) {
    $allSoftware | Export-Csv -Path $CsvOut -NoTypeInformation
    Write-Host "CSV written: $CsvOut"
  }
  if ($JsonOut) {
    [PSCustomObject]@{
      Software = $allSoftware
      SecurityDetections = $allDetections
    } | ConvertTo-Json -Depth 6 | Set-Content -Path $JsonOut -Encoding UTF8
    Write-Host "JSON written: $JsonOut"
  }

  # Default pipeline output: software rows + detections (tagged by Section)
  $allSoftware + $allDetections
}



# Local machine, table view
# .\Get-InstalledSoftware.ps1 | Sort-Object DisplayName | Format-Table DisplayName,DisplayVersion,Publisher -Auto

# Remote scan with creds + CSV
# .\Get-InstalledSoftware.ps1 -ComputerName PC01,SRV01 -Credential (Get-Credential) -CsvOut .\software.csv

# Include WMIC fallback (slow; last resort) and export JSON
# .\Get-InstalledSoftware.ps1 -ComputerName (Get-Content .\hosts.txt) -UseWmic -JsonOut .\inventory.json

# Show only detected security/RMM products
# .\Get-InstalledSoftware.ps1 | Where-Object Section -eq 'SecurityDetection' | Format-Table -Auto

