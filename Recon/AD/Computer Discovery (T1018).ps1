# === Active Directory Computer Discovery (T1018) ===
# Enumerates domain computers and potential targets for lateral movement
# Maps to MITRE ATT&CK T1018 - Remote System Discovery

param(
    [string]$Domain = "",
    [string]$Server = "",
    [int]$MaxComputers = 1000,
    [switch]$ServersOnly = $false
)

$results = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"

Write-Host "[*] Starting Computer Discovery (T1018)..." -ForegroundColor Cyan

try {
    # Import AD module if available
    if (Get-Module -Name ActiveDirectory -ListAvailable) {
        Import-Module ActiveDirectory -ErrorAction Stop
    } else {
        throw "Active Directory module not available. Run Install_RSAT.ps1 first."
    }
    
    # Domain parameters
    $domainParams = @{}
    if ($Domain) { $domainParams['Identity'] = $Domain }
    if ($Server) { $domainParams['Server'] = $Server }
    
    $currentDomain = Get-ADDomain @domainParams
    Write-Host "[+] Targeting domain: $($currentDomain.DNSRoot)" -ForegroundColor Green
    
    # Computer filter
    $computerFilter = "ObjectClass -eq 'computer'"
    if ($ServersOnly) {
        $computerFilter += " -and OperatingSystem -like '*Server*'"
    }
    
    Write-Host "[*] Enumerating domain computers..." -ForegroundColor Yellow
    $computers = Get-ADComputer -Filter $computerFilter -Properties * @domainParams | Select-Object -First $MaxComputers
    
    foreach ($computer in $computers) {
        try {
            # Ping test for live systems
            $pingResult = Test-Connection -ComputerName $computer.DNSHostName -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            $results += [PSCustomObject]@{
                ComputerName = $computer.Name
                DNSHostName = $computer.DNSHostName
                IPv4Address = $computer.IPv4Address
                OperatingSystem = $computer.OperatingSystem
                OSVersion = $computer.OperatingSystemVersion
                ServicePack = $computer.OperatingSystemServicePack
                LastLogon = if($computer.LastLogonDate) { $computer.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                Enabled = $computer.Enabled
                Created = $computer.Created.ToString("yyyy-MM-dd HH:mm:ss")
                Location = $computer.Location
                Description = $computer.Description
                ManagedBy = $computer.ManagedBy
                DistinguishedName = $computer.DistinguishedName
                IsOnline = if($pingResult) { "Yes" } else { "No" }
                ServerRole = if($computer.OperatingSystem -like "*Server*") { "Server" } else { "Workstation" }
                Notes = "Domain Computer"
            }
        }
        catch {
            # Add computer even if some properties fail
            $results += [PSCustomObject]@{
                ComputerName = $computer.Name
                DNSHostName = $computer.DNSHostName
                IPv4Address = "Unknown"
                OperatingSystem = $computer.OperatingSystem
                OSVersion = "Unknown"
                ServicePack = "Unknown"
                LastLogon = "Unknown"
                Enabled = $computer.Enabled
                Created = "Unknown"
                Location = "Unknown"
                Description = $computer.Description
                ManagedBy = "Unknown"
                DistinguishedName = $computer.DistinguishedName
                IsOnline = "Unknown"
                ServerRole = if($computer.OperatingSystem -like "*Server*") { "Server" } else { "Workstation" }
                Notes = "Limited Information"
            }
        }
    }
    
    Write-Host "[+] Found $($computers.Count) domain computers" -ForegroundColor Green
    
    # Categorize results
    $servers = $results | Where-Object { $_.ServerRole -eq "Server" }
    $workstations = $results | Where-Object { $_.ServerRole -eq "Workstation" }
    $onlineComputers = $results | Where-Object { $_.IsOnline -eq "Yes" }
    
    # Get domain controllers separately
    Write-Host "[*] Identifying domain controllers..." -ForegroundColor Yellow
    $domainControllers = Get-ADDomainController -Filter * @domainParams
    
    foreach ($dc in $domainControllers) {
        # Update existing entry or add new one
        $existingDC = $results | Where-Object { $_.ComputerName -eq $dc.Name }
        if ($existingDC) {
            $existingDC.Notes = "Domain Controller"
            $existingDC.ServerRole = "Domain Controller"
        } else {
            $results += [PSCustomObject]@{
                ComputerName = $dc.Name
                DNSHostName = $dc.HostName
                IPv4Address = $dc.IPv4Address
                OperatingSystem = $dc.OperatingSystem
                OSVersion = $dc.OperatingSystemVersion
                ServicePack = "Unknown"
                LastLogon = "N/A"
                Enabled = "Yes"
                Created = "Unknown"
                Location = $dc.Site
                Description = "Domain Controller"
                ManagedBy = "N/A"
                DistinguishedName = $dc.ComputerObjectDN
                IsOnline = "Yes"
                ServerRole = "Domain Controller"
                Notes = "Domain Controller"
            }
        }
    }
    
    Write-Host "[+] Identified $($domainControllers.Count) domain controllers" -ForegroundColor Green
    
    # Output summary
    Write-Host ""
    Write-Host "Computer Discovery Summary:" -ForegroundColor Cyan
    Write-Host "- Domain: $($currentDomain.DNSRoot)" -ForegroundColor White
    Write-Host "- Total Computers: $($results.Count)" -ForegroundColor White
    Write-Host "- Servers: $($servers.Count)" -ForegroundColor White
    Write-Host "- Workstations: $($workstations.Count)" -ForegroundColor White
    Write-Host "- Domain Controllers: $($domainControllers.Count)" -ForegroundColor White
    Write-Host "- Online Systems: $($onlineComputers.Count)" -ForegroundColor White
    Write-Host "- Timestamp: $timestamp" -ForegroundColor White
    
    return $results
    
} catch {
    Write-Host "[!] Computer discovery failed: $($_.Exception.Message)" -ForegroundColor Red
    
    # Fallback to net commands
    Write-Host "[*] Attempting fallback enumeration..." -ForegroundColor Yellow
    
    try {
        $netView = net view /domain 2>$null
        if ($LASTEXITCODE -eq 0) {
            $computerLines = $netView | Select-String "^\\\\" | ForEach-Object { 
                $_.Line.Split()[0].TrimStart("\\") 
            }
            
            foreach ($computerName in $computerLines) {
                $results += [PSCustomObject]@{
                    ComputerName = $computerName
                    DNSHostName = "$computerName.$($env:USERDNSDOMAIN)"
                    IPv4Address = "Unknown"
                    OperatingSystem = "Unknown"
                    OSVersion = "Unknown"
                    ServicePack = "Unknown"
                    LastLogon = "Unknown"
                    Enabled = "Unknown"
                    Created = "Unknown"
                    Location = "Unknown"
                    Description = "Unknown"
                    ManagedBy = "Unknown"
                    DistinguishedName = "Unknown"
                    IsOnline = "Unknown"
                    ServerRole = "Unknown"
                    Notes = "Fallback Enumeration"
                }
            }
            
            Write-Host "[+] Fallback enumeration found $($results.Count) computers" -ForegroundColor Green
            return $results
        } else {
            throw "Net view enumeration also failed"
        }
    }
    catch {
        Write-Host "[!] All enumeration methods failed" -ForegroundColor Red
        return @()
    }
}