# === Active Directory Domain User Discovery (T1087.002) ===
# Enumerates domain users with focus on privileged accounts
# Maps to MITRE ATT&CK T1087.002 - Account Discovery: Domain Account

param(
    [string]$Domain = "",
    [string]$Server = "",
    [int]$MaxUsers = 1000,
    [switch]$PrivilegedOnly = $false
)

function Write-Output {
    param($Object)
    $Object | Format-Table -AutoSize | Out-String
}

$results = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"

Write-Host "[*] Starting Domain User Discovery (T1087.002)..." -ForegroundColor Cyan

try {
    # Import AD module if available
    if (Get-Module -Name ActiveDirectory -ListAvailable) {
        Import-Module ActiveDirectory -ErrorAction Stop
    } else {
        throw "Active Directory module not available. Run Install_RSAT.ps1 first."
    }
    
    # Get domain info
    $domainParams = @{}
    if ($Domain) { $domainParams['Identity'] = $Domain }
    if ($Server) { $domainParams['Server'] = $Server }
    
    $currentDomain = Get-ADDomain @domainParams
    Write-Host "[+] Targeting domain: $($currentDomain.DNSRoot)" -ForegroundColor Green
    
    # Privileged groups to focus on
    $privilegedGroups = @(
        "Domain Admins",
        "Enterprise Admins", 
        "Schema Admins",
        "Administrators",
        "Account Operators",
        "Server Operators",
        "Backup Operators",
        "Print Operators",
        "DNSAdmins",
        "Exchange Organization Administrators"
    )
    
    # Get privileged users first
    Write-Host "[*] Enumerating privileged users..." -ForegroundColor Yellow
    $privilegedUsers = @()
    
    foreach ($group in $privilegedGroups) {
        try {
            $groupMembers = Get-ADGroupMember -Identity $group @domainParams -ErrorAction SilentlyContinue
            foreach ($member in $groupMembers) {
                if ($member.objectClass -eq "user") {
                    $userDetails = Get-ADUser -Identity $member.SamAccountName -Properties * @domainParams -ErrorAction SilentlyContinue
                    if ($userDetails) {
                        $privilegedUsers += [PSCustomObject]@{
                            Username = $userDetails.SamAccountName
                            DisplayName = $userDetails.DisplayName
                            Email = $userDetails.EmailAddress
                            Enabled = $userDetails.Enabled
                            LastLogon = if($userDetails.LastLogonDate) { $userDetails.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                            PrivilegedGroup = $group
                            DistinguishedName = $userDetails.DistinguishedName
                            Created = $userDetails.Created.ToString("yyyy-MM-dd HH:mm:ss")
                            PasswordLastSet = if($userDetails.PasswordLastSet) { $userDetails.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                            AdminCount = $userDetails.AdminCount
                            Department = $userDetails.Department
                            Title = $userDetails.Title
                            Manager = $userDetails.Manager
                            Notes = "Privileged Account"
                        }
                    }
                }
            }
        }
        catch {
            Write-Host "[!] Could not enumerate group: $group" -ForegroundColor Yellow
        }
    }
    
    $results += $privilegedUsers | Sort-Object Username -Unique
    Write-Host "[+] Found $($privilegedUsers.Count) privileged users" -ForegroundColor Green
    
    # Get general domain users if not privileged-only
    if (-not $PrivilegedOnly) {
        Write-Host "[*] Enumerating general domain users..." -ForegroundColor Yellow
        
        $userFilter = "ObjectClass -eq 'user'"
        $allUsers = Get-ADUser -Filter $userFilter -Properties * @domainParams | Select-Object -First $MaxUsers
        
        foreach ($user in $allUsers) {
            # Skip if already in privileged list
            if ($privilegedUsers.Username -notcontains $user.SamAccountName) {
                $results += [PSCustomObject]@{
                    Username = $user.SamAccountName
                    DisplayName = $user.DisplayName
                    Email = $user.EmailAddress
                    Enabled = $user.Enabled
                    LastLogon = if($user.LastLogonDate) { $user.LastLogonDate.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                    PrivilegedGroup = "N/A"
                    DistinguishedName = $user.DistinguishedName
                    Created = $user.Created.ToString("yyyy-MM-dd HH:mm:ss")
                    PasswordLastSet = if($user.PasswordLastSet) { $user.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "Never" }
                    AdminCount = $user.AdminCount
                    Department = $user.Department
                    Title = $user.Title
                    Manager = $user.Manager
                    Notes = "Standard User"
                }
            }
        }
        
        Write-Host "[+] Found $($allUsers.Count) total domain users" -ForegroundColor Green
    }
    
    # Service accounts detection
    Write-Host "[*] Identifying potential service accounts..." -ForegroundColor Yellow
    $serviceAccounts = $results | Where-Object { 
        $_.Username -like "*svc*" -or 
        $_.Username -like "*service*" -or
        $_.Username -like "*sql*" -or
        $_.Username -like "*exchange*" -or
        $_.Notes -eq "Standard User" -and $_.PasswordLastSet -eq "Never"
    }
    
    foreach ($svcAccount in $serviceAccounts) {
        $svcAccount.Notes = "Potential Service Account"
    }
    
    Write-Host "[+] Identified $($serviceAccounts.Count) potential service accounts" -ForegroundColor Green
    
    # Output summary
    Write-Host ""
    Write-Host "Domain User Discovery Summary:" -ForegroundColor Cyan
    Write-Host "- Domain: $($currentDomain.DNSRoot)" -ForegroundColor White
    Write-Host "- Total Users Found: $($results.Count)" -ForegroundColor White
    Write-Host "- Privileged Users: $($privilegedUsers.Count)" -ForegroundColor White
    Write-Host "- Service Accounts: $($serviceAccounts.Count)" -ForegroundColor White
    Write-Host "- Timestamp: $timestamp" -ForegroundColor White
    
    return $results
    
} catch {
    Write-Host "[!] Domain user discovery failed: $($_.Exception.Message)" -ForegroundColor Red
    
    # Fallback to net commands
    Write-Host "[*] Attempting fallback enumeration..." -ForegroundColor Yellow
    
    try {
        $netUsers = net user /domain 2>$null
        if ($LASTEXITCODE -eq 0) {
            $userLines = $netUsers | Select-String "^[a-zA-Z]" | ForEach-Object { $_.Line.Split() } | Where-Object { $_ -ne "" }
            
            foreach ($username in $userLines) {
                $results += [PSCustomObject]@{
                    Username = $username
                    DisplayName = "Unknown"
                    Email = "Unknown"
                    Enabled = "Unknown"
                    LastLogon = "Unknown"
                    PrivilegedGroup = "Unknown"
                    DistinguishedName = "Unknown"
                    Created = "Unknown"
                    PasswordLastSet = "Unknown"
                    AdminCount = "Unknown"
                    Department = "Unknown"
                    Title = "Unknown"
                    Manager = "Unknown"
                    Notes = "Fallback Enumeration"
                }
            }
            
            Write-Host "[+] Fallback enumeration found $($results.Count) users" -ForegroundColor Green
            return $results
        } else {
            throw "Net command enumeration also failed"
        }
    }
    catch {
        Write-Host "[!] All enumeration methods failed" -ForegroundColor Red
        return @()
    }
}