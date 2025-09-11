<#
.SYNOPSIS
  Discover potential config/credential files by name, extension, and content.

.DESCRIPTION
  - Name/extension match: conf, cfg, ini, env, json, yaml, yml, xml, ps1/psm1, sh, bat, k8s manifests, db files; plus Office/PDF names.
  - Content match (optional): password=, secret=, key=, connection strings, tokens, private keys, AWS AKIA*, etc.
  - Skips noisy/system folders by default; customizable.
  - Works locally or via \\HOST\C$ admin shares.
  - Outputs: Host, Path, Size, LastWriteTime, Reason (Name/Ext/Content), MatchedText (snippet), Hash (optional), Owner.

.PARAMETER Path
  Root directories to scan. Default: all fixed drives on the local host.

.PARAMETER ComputerName
  Remote hosts to scan via admin shares (\\HOST\C$). Requires rights & firewall.

.PARAMETER IncludeContent
  Enable content scanning (Select-String) with built-in regex signatures.

.PARAMETER MaxFileMB
  Skip files larger than this for content scanning (default 20 MB).

.PARAMETER IncludeHidden
  Include Hidden/System files and folders (default: off).

.PARAMETER Depth
  Max folder depth (default: unlimited).

.PARAMETER CsvOut / JsonOut
  Export results.

.PARAMETER IncludeHash
  Add SHA256 file hash (slower).

.PARAMETER ExtraNameKeywords
  Additional name keywords (e.g., 'creds','db','backup').

.PARAMETER ExtraExtensions
  Additional extensions (e.g., '.kdbx','.pgpass').
#>

[CmdletBinding()]
param(
  [string[]] $Path,

  [string[]] $ComputerName,

  [switch]   $IncludeContent,
  [int]      $MaxFileMB = 20,
  [int]      $Depth,

  [switch]   $IncludeHidden,
  [switch]   $IncludeHash,

  [string]   $CsvOut,
  [string]   $JsonOut,

  [string[]] $ExtraNameKeywords,
  [string[]] $ExtraExtensions
)

begin {
  function Invoke-Safe { param([scriptblock]$b) try { & $b } catch { $null } }

  # --- Target roots ---------------------------------------------------------
  function Get-DefaultRoots {
    Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" |
      ForEach-Object { "$($_.DeviceID)\" }
  }

  # --- Build search specs ---------------------------------------------------
  $NameKeywords = @(
    'pass','passwd','password','secret','token','credential','creds','apikey','api_key','conn','connection',
    'db','database','mongo','mysql','postgres','mssql','redis','kafka','rabbit','vault',
    'config','conf','cfg','settings','env','.env','kube','k8s','docker','compose','terraform','pulumi'
  ) + ($ExtraNameKeywords | Where-Object { $_ })

  $Extensions = @(
    '.conf','.cfg','.cnf','.ini','.env','.json','.yaml','.yml','.xml',
    '.ps1','.psm1','.bat','.cmd','.vbs','.sh','.py','.rb','.php','.js','.ts',
    '.pem','.ppk','.key','.crt','.pfx','.kubeconfig','.sql','.udl',
    '.xlsx','.xls','.docx','.doc','.pdf','.txt','.log'
  ) + ($ExtraExtensions | Where-Object { $_ })

  # Quick binary extensions to skip in content scans
  $LikelyBinary = @('.exe','.dll','.sys','.iso','.img','.vhd','.vhdx','.zip','.7z','.rar','.gz','.xz','.msi','.cab')

  # Content signatures (conservative but useful)
  $ContentRegexes = @(
    '(?i)\b(password|passwd|pwd)\s*[:=]\s*[^;\r\n]{3,}',
    '(?i)\b(secret|secret_key|secretKey|client_secret)\s*[:=]\s*[^;\r\n]{6,}',
    '(?i)\b(token|bearer|access_token|refresh_token)\s*[:=]\s*[A-Za-z0-9\-_\.=]{10,}',
    '(?i)\b(connection\s*string|conn[_\-]?str|Data Source=|Server=.+;Database=|Host=.+;Database=)',
    '(?i)\bUser\s*ID=.+;Password=.+;',
    'AKIA[0-9A-Z]{16}',         # AWS Access Key ID
    'ASIA[0-9A-Z]{16}',         # AWS STS
    '(?ms)-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----.*?-----END \1 PRIVATE KEY-----',
    '(?i)\b(sas_token|sig=)[A-Za-z0-9%+/=]{10,}', # Azure/GCP-ish signed tokens
    '(?i)\b(pgpass|PGPASSWORD|MYSQL_PWD)\b\s*[:=]\s*[^;\r\n]{3,}'
  )

  # Default excludes (speed + noise)
  $DefaultExcludes = @(
    '\\Windows(\\|$)','\\Program Files( \(x86\))?(\\|$)','\\ProgramData(\\|$)','\\AppData(\\|$)',
    '\\Recovery(\\|$)','\\$Recycle\.Bin(\\|$)','\\System Volume Information(\\|$)',
    '\\node_modules(\\|$)','\\.git(\\|$)','\\.venv(\\|$)','\\venv(\\|$)','\\.terraform(\\|$)','\\.pulumi(\\|$)'
  )

  function Should-ExcludePath {
    param([string]$FullPath)
    foreach ($rx in $DefaultExcludes) { if ($FullPath -ireplace '\\','\' -match $rx) { return $true } }
    return $false
  }

  function Is-BinaryLike {
    param([string]$Path)
    $ext = [System.IO.Path]::GetExtension($Path)
    return ($LikelyBinary -contains $ext.ToLower())
  }

  function Get-OwnerSafe {
    param([System.IO.FileInfo]$fi)
    try { (Get-Acl -LiteralPath $fi.FullName).Owner } catch { $null }
  }

  function Hash-File {
    param([string]$FullPath)
    try { (Get-FileHash -Algorithm SHA256 -LiteralPath $FullPath).Hash } catch { $null }
  }

  function New-Result {
    param($Host,$fi,$reason,$match)
    [PSCustomObject]@{
      Host          = $Host
      FullPath      = $fi.FullName
      Name          = $fi.Name
      Extension     = $fi.Extension
      SizeBytes     = $fi.Length
      LastWriteTime = $fi.LastWriteTime
      Owner         = Get-OwnerSafe -fi $fi
      Reason        = $reason
      MatchedText   = $match
      HashSHA256    = $null
    }
  }

  function Get-RootsForHost {
    param([string]$Host)
    if ($Host -in @('localhost',$env:COMPUTERNAME,'.','127.0.0.1')) {
      return $Path ?? (Get-DefaultRoots)
    }
    # For remote host via admin share, translate to \\HOST\C$ roots
    $roots = @()
    if ($Path) {
      foreach ($p in $Path) {
        if ($p -match '^[A-Za-z]:\\') {
          $drive = $p.Substring(0,1)
          $rest  = $p.Substring(3)
          $roots += "\\$Host\$drive`$\$rest"
        } else {
          $roots += "\\$Host\C$\$p"
        }
      }
    } else {
      # enumerate fixed drives remotely (best effort)
      $drives = Invoke-Safe { (Get-CimInstance -ComputerName $Host Win32_LogicalDisk -Filter "DriveType=3").DeviceID }
      if ($drives) {
        foreach ($d in $drives) { $roots += "\\$Host\$($d.Substring(0,1))$\" }
      } else {
        $roots = @("\\$Host\C$\")
      }
    }
    $roots
  }
}

process {
  $hosts = @()
  if ($ComputerName) { $hosts += $ComputerName } else { $hosts += @('localhost') }

  $findings = New-Object System.Collections.Generic.List[object]

  foreach ($host in $hosts) {
    $roots = Get-RootsForHost -Host $host

    foreach ($root in $roots) {
      if (-not (Test-Path -LiteralPath $root)) { continue }

      $dirParams = @{
        LiteralPath = $root
        Recurse     = $true
        File        = $true
        ErrorAction = 'SilentlyContinue'
      }
      if ($Depth) { $dirParams['Depth'] = $Depth }
      if (-not $IncludeHidden) { $dirParams['Attributes'] = '!Hidden,!System' }

      # Enumerate files quickly
      Invoke-Safe { Get-ChildItem @dirParams } | ForEach-Object {
        $fi = $_
        $full = $fi.FullName

        if (Should-ExcludePath -FullPath $full) { return }

        $nameHit = $false
        foreach ($kw in $NameKeywords) {
          if ($fi.Name -match [Regex]::Escape($kw)) { $nameHit = $true; break }
        }
        $extHit = ($Extensions -contains $fi.Extension.ToLower())

        if ($nameHit -or $extHit) {
          $findings.Add( (New-Result -Host $host -fi $fi -reason ('Name/Ext: ' + ($nameHit?'name ':'') + ($extHit?'ext':'')) -match $null) ) | Out-Null
        }

        if ($IncludeContent) {
          if ($fi.Length -gt ($MaxFileMB * 1MB)) { return }
          if (Is-BinaryLike -Path $full) { return }

          # Content scan (stop at first match per file for speed)
          $text = Invoke-Safe { Get-Content -LiteralPath $full -ErrorAction Stop -Raw -Encoding utf8 }
          if (-not $text) { return }

          foreach ($rx in $ContentRegexes) {
            $m = [Regex]::Match($text, $rx, 'IgnoreCase')
            if ($m.Success) {
              $snippet = $m.Value
              if ($snippet.Length -gt 200) { $snippet = $snippet.Substring(0,200) + '…' }
              $row = New-Result -Host $host -fi $fi -reason "Content:$rx" -match $snippet
              if ($IncludeHash) { $row.HashSHA256 = Hash-File -FullPath $full }
              $findings.Add($row) | Out-Null
              break
            }
          }
        }
      }
    }
  }

  # Exports
  if ($CsvOut) {
    $findings | Export-Csv -Path $CsvOut -NoTypeInformation
    Write-Host "CSV written: $CsvOut"
  }
  if ($JsonOut) {
    $findings | ConvertTo-Json -Depth 5 | Set-Content -Path $JsonOut -Encoding UTF8
    Write-Host "JSON written: $JsonOut"
  }

  $findings
}
