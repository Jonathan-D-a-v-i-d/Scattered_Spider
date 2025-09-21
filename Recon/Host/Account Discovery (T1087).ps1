<#
.SYNOPSIS
  Audit local & domain user accounts with a focus on administrative privileges.

.DESCRIPTION
  - Local: Enumerates local Administrators group membership on each computer
           (via CIM; fallback to "net localgroup administrators" parsing).
  - Domain: Enumerates privileged AD groups (Domain Admins, Enterprise Admins, etc.)
            using Get-AD* cmdlets if available; falls back to "net group ... /domain".
  - Also lists all domain users (basic inventory) when AD module is available.
  - Resolves nested group membership for domain privileged groups.

.PARAMETER ComputerName
  Computers to audit for local Administrators membership. Defaults to localhost.

.PARAMETER TargetsFile
  File with one computer per line.

.PARAMETER Credential
  Optional credential for remote CIM calls and AD queries.

.PARAMETER DomainGroups
  Domain privileged groups to check. Defaults to common AD built-ins.

.PARAMETER CsvOut, JsonOut
  Optional export paths.

.EXAMPLES
  .\Get-PrivAudit.ps1
  .\Get-PrivAudit.ps1 -ComputerName PC01,SRV01 -Credential (Get-Credential) -CsvOut .\priv_audit.csv
  .\Get-PrivAudit.ps1 -TargetsFile .\hosts.txt -JsonOut .\priv_audit.json
#>

[CmdletBinding()]
param(
  [string[]] $ComputerName = @($env:COMPUTERNAME),
  [string]   $TargetsFile,
  [pscredential] $Credential,

  [string[]] $DomainGroups = @(
    'Domain Admins','Enterprise Admins','Schema Admins',
    'Administrators','Account Operators','Server Operators',
    'Backup Operators','Print Operators','DNSAdmins'
  ),

  [string] $CsvOut,
  [string] $JsonOut
)

begin {
  function Invoke-Safe { param([scriptblock]$Block) try { & $Block } catch { $null } }

  # -- Helpers ---------------------------------------------------------------

  function Test-ADAvailable {
    if (Get-Module -ListAvailable -Name ActiveDirectory) {
      Import-Module ActiveDirectory -ErrorAction SilentlyContinue | Out-Null
      return $true
    }
    return $false
  }

  function Get-DomainNetbios {
    # Tries to determine NetBIOS domain name (for net group fallbacks)
    $dns = $env:USERDNSDOMAIN
    $nb  = $env:USERDOMAIN
    if ($nb) { return $nb }
    if ($dns) { return $dns.Split('.')[0] }
    return $null
  }

  # -- LOCAL ADMINISTRATORS (CIM first, fallback to 'net localgroup') --------

  function Get-LocalAdministratorsCim {
    param([string]$Computer, [pscredential]$Cred)

    # Find the local Administrators group instance
    $grp = Invoke-Safe {
      Get-CimInstance -Class Win32_Group -ComputerName $Computer -Credential $Cred `
        -Filter "LocalAccount=TRUE AND Name='Administrators'"
    }
    if (-not $grp) { return @() }

    # Query memberships using association class Win32_GroupUser
    $q = "ASSOCIATORS OF {Win32_Group.Domain='$($grp.Domain)',Name='$($grp.Name)'} WHERE ResultClass=Win32_Account"
    $members = Invoke-Safe {
      Get-CimInstance -Query $q -ComputerName $Computer -Credential $Cred
    }
    if (-not $members) { return @() }

    foreach ($m in $members) {
      [PSCustomObject]@{
        Section     = 'LocalAdmins'
        Host        = $Computer
        MemberName  = "$($m.Domain)\$($m.Name)"
        MemberClass = if ($m.ObjectClass) { $m.ObjectClass } else { 'Unknown' }
        Source      = 'CIM:Win32_Group -> Win32_Account'
        Notes       = $null
      }
    }
  }

  function Get-LocalAdministratorsNet {
    param([string]$Computer)

    $rows = if ($Computer -ieq $env:COMPUTERNAME -or $Computer -in @('127.0.0.1','localhost','.')) {
      Invoke-Safe { (net localgroup administrators) 2>$null }
    } else {
      # Remote query via ADMIN$ IPC might not be possible; still try plain net (depends on auth)
      Invoke-Safe { (net localgroup administrators "\\$Computer") 2>$null } # If fails, $rows is $null
    }
    if (-not $rows) { return @() }

    $members = @()
    $capture = $false
    foreach ($line in $rows) {
      if ($line -match '^-+$') { $capture = -not $capture; continue }
      if ($capture -and $line.Trim() -and $line -notmatch '(command completed|successfully)') {
        $name = $line.Trim()
        # Skip empty lines and command status messages
        if ($name -and $name -ne '') {
          # normalize local accounts without domain prefix
          if ($name -notmatch '^[^\\]+\\') { $name = "$Computer\$name" }
          $members += [PSCustomObject]@{
            Section     = 'LocalAdmins'
            Host        = $Computer
            MemberName  = $name
            MemberClass = 'Unknown'
            Source      = 'net localgroup administrators'
            Notes       = $null
          }
        }
      }
    }
    $members
  }

  # -- DOMAIN PRIVILEGED GROUPS ---------------------------------------------

  function Expand-ADGroupRecursive {
    param([string]$GroupSam, [pscredential]$Cred)

    $seen = New-Object System.Collections.Generic.HashSet[string]
    $out  = New-Object System.Collections.Generic.List[object]

    $stack = New-Object System.Collections.Stack
    $stack.Push($GroupSam)

    while ($stack.Count -gt 0) {
      $g = $stack.Pop()
      if ($seen.Contains($g)) { continue } [void]$seen.Add($g)

      $members = if ($Cred) {
        Invoke-Safe { Get-ADGroupMember -Identity $g -Recursive -Credential $Cred -ErrorAction Stop }
      } else {
        Invoke-Safe { Get-ADGroupMember -Identity $g -Recursive -ErrorAction Stop }
      }
      if (-not $members) { continue }

      foreach ($m in $members) {
        $isGroup = ($m.ObjectClass -eq 'group')
        $item = [PSCustomObject]@{
          Section     = 'DomainPrivGroup'
          Group       = $g
          MemberSam   = $m.SamAccountName
          MemberDN    = $m.DistinguishedName
          MemberType  = $m.ObjectClass
          Source      = 'Get-ADGroupMember -Recursive'
          Notes       = $null
        }
        $out.Add($item) | Out-Null

        if ($isGroup) { $stack.Push($m.SamAccountName) }
      }
    }

    $out
  }

  function Get-DomainPrivsFallbackNet {
    param([string[]]$Groups)

    $domainNB = Get-DomainNetbios
    if (-not $domainNB) { return @() }

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($g in $Groups) {
      $out = Invoke-Safe { (net group "$g" /domain) 2>$null }
      if (-not $out) { continue }

      $capture = $false
      foreach ($line in $out) {
        # Text block delimited by dashed lines; members are simple tokens
        if ($line -match '^---') { $capture = -not $capture; continue }
        if ($capture) {
          $tokens = $line -split '\s+' | Where-Object { $_ -and $_ -ne 'The' -and $_ -ne 'command' }
          foreach ($t in $tokens) {
            $rows.Add([PSCustomObject]@{
              Section     = 'DomainPrivGroup'
              Group       = $g
              MemberSam   = $t
              MemberDN    = $null
              MemberType  = 'unknown'
              Source      = 'net group /domain'
              Notes       = $null
            }) | Out-Null
          }
        }
      }
    }
    $rows
  }

  function Get-ADUsersBasic {
    param([pscredential]$Cred)

    $props = @('SamAccountName','Enabled','WhenCreated','pwdLastSet','LastLogonDate','UserPrincipalName','DisplayName')
    $users = if ($Cred) {
      Invoke-Safe { Get-ADUser -Filter * -Properties $props -Credential $Cred }
    } else {
      Invoke-Safe { Get-ADUser -Filter * -Properties $props }
    }
    if (-not $users) { return @() }

    $users | ForEach-Object {
      [PSCustomObject]@{
        Section          = 'DomainUser'
        SamAccountName   = $_.SamAccountName
        DisplayName      = $_.DisplayName
        UPN              = $_.UserPrincipalName
        Enabled          = $_.Enabled
        WhenCreated      = $_.WhenCreated
        LastLogonDate    = $_.LastLogonDate
        PwdLastSet       = if ($_.pwdLastSet) { [DateTime]::FromFileTime($_.pwdLastSet) } else { $null }
        Source           = 'Get-ADUser'
      }
    }
  }

  $adAvailable = Test-ADAvailable
}

process {
  # Build target set
  $targets = New-Object System.Collections.Generic.HashSet[string]
  foreach ($c in $ComputerName) { if ($c) { [void]$targets.Add($c) } }
  if ($TargetsFile -and (Test-Path $TargetsFile)) {
    Get-Content $TargetsFile | Where-Object { $_ } | ForEach-Object { [void]$targets.Add($_) }
  }

  $results = New-Object System.Collections.Generic.List[object]

  # 1) Local Administrators on each host
  foreach ($t in $targets) {
    $loc = Get-LocalAdministratorsCim -Computer $t -Cred $Credential
    if (-not $loc -or $loc.Count -eq 0) {
      $loc = Get-LocalAdministratorsNet -Computer $t
      if (-not $loc -or $loc.Count -eq 0) {
        $results.Add([PSCustomObject]@{
          Section='LocalAdmins'; Host=$t; MemberName=$null; MemberClass=$null; Source='None'; Notes='Unable to enumerate local admins'
        }) | Out-Null
        continue
      }
    }
    foreach ($row in $loc) { $results.Add($row) | Out-Null }
  }

  # 2) Domain privileged group membership
  if ($adAvailable) {
    foreach ($g in $DomainGroups | Where-Object { $_ }) {
      $exp = Expand-ADGroupRecursive -GroupSam $g -Cred $Credential
      foreach ($row in $exp) { $results.Add($row) | Out-Null }
    }
  } else {
    $fallback = Get-DomainPrivsFallbackNet -Groups $DomainGroups
    foreach ($row in $fallback) { $results.Add($row) | Out-Null }
  }

  # 3) Domain user inventory (basic)
  if ($adAvailable) {
    $du = Get-ADUsersBasic -Cred $Credential
    foreach ($row in $du) { $results.Add($row) | Out-Null }
  } else {
    # Very light fallback to "net user /domain" list
    $list = Invoke-Safe { (net user /domain) 2>$null }
    if ($list) {
      $capture = $false
      foreach ($line in $list) {
        if ($line -match '^---') { $capture = -not $capture; continue }
        if ($capture) {
          ($line -split '\s+') | Where-Object { $_ } | ForEach-Object {
            $results.Add([PSCustomObject]@{
              Section='DomainUser'; SamAccountName=$_; DisplayName=$null; UPN=$null; Enabled=$null
              WhenCreated=$null; LastLogonDate=$null; PwdLastSet=$null; Source='net user /domain'
            }) | Out-Null
          }
        }
      }
    }
  }

  # 4) Derive "Effective Admins per Host" quick view
  #    Mark members in LocalAdmins that are also in domain privileged groups
  $domainPrivSet = New-Object System.Collections.Generic.HashSet[string]  # holds DOMAIN\sam
  foreach ($r in $results | Where-Object { $_.Section -eq 'DomainPrivGroup' -and $_.MemberSam }) {
    # Attempt to prefix with USERDOMAIN if missing—best effort heuristic
    $domainPrefix = $env:USERDOMAIN
    $key = if ($r.MemberSam -match '^[^\\]+\\') { $r.MemberSam } elseif ($domainPrefix) { "$domainPrefix\$($r.MemberSam)" } else { $r.MemberSam }
    [void]$domainPrivSet.Add($key.ToUpperInvariant())
  }

  foreach ($la in $results | Where-Object { $_.Section -eq 'LocalAdmins' -and $_.MemberName }) {
    $isPriv = $domainPrivSet.Contains($la.MemberName.ToUpperInvariant())
    $results.Add([PSCustomObject]@{
      Section      = 'EffectivePriv'
      Host         = $la.Host
      Member       = $la.MemberName
      IsPrivileged = $isPriv -or ($la.MemberName -match '^(BUILTIN|NT AUTHORITY)\\')
      Source       = 'Derived(LocalAdmins ∩ DomainPrivs)'
    }) | Out-Null
  }

  # Output & exports
  if ($CsvOut) {
    $results | Export-Csv -Path $CsvOut -NoTypeInformation
    Write-Host "CSV written: $CsvOut"
  }
  if ($JsonOut) {
    $results | ConvertTo-Json -Depth 6 | Set-Content -Path $JsonOut -Encoding UTF8
    Write-Host "JSON written: $JsonOut"
  }

  $results
}



# Local machine only
# .\Get-PrivAudit.ps1 | Where-Object Section -eq 'LocalAdmins' | Format-Table -Auto

# Multiple hosts + export
# .\Get-PrivAudit.ps1 -ComputerName PC01,SRV01,FS01 -Credential (Get-Credential) -CsvOut .\priv_audit.csv

# From file + JSON
# .\Get-PrivAudit.ps1 -TargetsFile .\hosts.txt -JsonOut .\priv_audit.json

# Only look at who is effectively privileged on each host
# .\Get-PrivAudit.ps1 | Where-Object Section -eq 'EffectivePriv' | Sort-Object Host,Member | Format-Table -Auto
