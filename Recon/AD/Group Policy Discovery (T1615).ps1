# === Group Policy Discovery (T1615) ===
# Enumerates Group Policy Objects and settings for privilege escalation opportunities
# Maps to MITRE ATT&CK T1615 - Group Policy Discovery

param(
    [string]$Domain = "",
    [string]$Server = "",
    [switch]$Detailed = $false
)

$results = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"

Write-Host "[*] Starting Group Policy Discovery (T1615)..." -ForegroundColor Cyan

try {
    # Import required modules
    if (Get-Module -Name ActiveDirectory -ListAvailable) {
        Import-Module ActiveDirectory -ErrorAction Stop
    } else {
        throw "Active Directory module not available. Run Install_RSAT.ps1 first."
    }
    
    if (Get-Module -Name GroupPolicy -ListAvailable) {
        Import-Module GroupPolicy -ErrorAction SilentlyContinue
        $gpModuleAvailable = $true
    } else {
        Write-Host "[!] GroupPolicy module not available, using limited enumeration" -ForegroundColor Yellow
        $gpModuleAvailable = $false
    }
    
    # Domain parameters
    $domainParams = @{}
    if ($Domain) { $domainParams['Identity'] = $Domain }
    if ($Server) { $domainParams['Server'] = $Server }
    
    $currentDomain = Get-ADDomain @domainParams
    Write-Host "[+] Targeting domain: $($currentDomain.DNSRoot)" -ForegroundColor Green
    
    if ($gpModuleAvailable) {
        # Get all GPOs
        Write-Host "[*] Enumerating Group Policy Objects..." -ForegroundColor Yellow
        $gpos = Get-GPO -All @domainParams
        
        foreach ($gpo in $gpos) {
            try {
                $gpoDetails = [PSCustomObject]@{
                    GPOName = $gpo.DisplayName
                    GPOID = $gpo.Id
                    Created = $gpo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Modified = $gpo.ModificationTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Owner = $gpo.Owner
                    Status = $gpo.GpoStatus
                    WMIFilter = if($gpo.WmiFilter) { $gpo.WmiFilter.Name } else { "None" }
                    ComputerVersion = $gpo.Computer.DSVersion
                    UserVersion = $gpo.User.DSVersion
                    Description = $gpo.Description
                    Type = "Group Policy Object"
                }
                
                # Get detailed settings if requested
                if ($Detailed) {
                    try {
                        $gpoReport = Get-GPOReport -Guid $gpo.Id -ReportType Xml @domainParams
                        # Parse interesting settings from XML
                        if ($gpoReport -match "PasswordPolicy|AccountLockout|UserRights|SecurityOptions") {
                            $gpoDetails | Add-Member -NotePropertyName "HasSecuritySettings" -NotePropertyValue "Yes"
                        } else {
                            $gpoDetails | Add-Member -NotePropertyName "HasSecuritySettings" -NotePropertyValue "No"
                        }
                        
                        if ($gpoReport -match "ScheduledTasks|Scripts|SoftwareInstallation") {
                            $gpoDetails | Add-Member -NotePropertyName "HasExecutionSettings" -NotePropertyValue "Yes"
                        } else {
                            $gpoDetails | Add-Member -NotePropertyName "HasExecutionSettings" -NotePropertyValue "No"
                        }
                    }
                    catch {
                        $gpoDetails | Add-Member -NotePropertyName "HasSecuritySettings" -NotePropertyValue "Unknown"
                        $gpoDetails | Add-Member -NotePropertyName "HasExecutionSettings" -NotePropertyValue "Unknown"
                    }
                }
                
                $results += $gpoDetails
            }
            catch {
                Write-Host "[!] Could not process GPO: $($gpo.DisplayName)" -ForegroundColor Yellow
            }
        }
        
        Write-Host "[+] Found $($gpos.Count) Group Policy Objects" -ForegroundColor Green
        
        # Get GPO links to OUs
        Write-Host "[*] Enumerating GPO links..." -ForegroundColor Yellow
        $ous = Get-ADOrganizationalUnit -Filter * @domainParams -Properties gpLink
        
        foreach ($ou in $ous) {
            if ($ou.gpLink) {
                $linkedGPOs = $ou.gpLink -split "\]\[" | ForEach-Object {
                    if ($_ -match "LDAP://cn=\{([^}]+)\}") {
                        $matches[1]
                    }
                }
                
                foreach ($linkedGPOId in $linkedGPOs) {
                    $linkedGPO = $gpos | Where-Object { $_.Id -eq $linkedGPOId }
                    if ($linkedGPO) {
                        $results += [PSCustomObject]@{
                            GPOName = $linkedGPO.DisplayName
                            GPOID = $linkedGPO.Id
                            Created = "N/A"
                            Modified = "N/A"
                            Owner = "N/A"
                            Status = "Linked"
                            WMIFilter = "N/A"
                            ComputerVersion = "N/A"
                            UserVersion = "N/A"
                            Description = "Linked to: $($ou.DistinguishedName)"
                            Type = "GPO Link"
                        }
                    }
                }
            }
        }
        
        # Check for interesting GPO settings patterns
        Write-Host "[*] Analyzing GPO configurations for security implications..." -ForegroundColor Yellow
        
        $securityGPOs = @()
        foreach ($gpo in $gpos) {
            try {
                $gpoXml = Get-GPOReport -Guid $gpo.Id -ReportType Xml @domainParams
                
                $riskFactors = @()
                if ($gpoXml -match "SeDebugPrivilege|SeTakeOwnershipPrivilege|SeLoadDriverPrivilege") {
                    $riskFactors += "Dangerous User Rights"
                }
                if ($gpoXml -match "PasswordPolicy.*PasswordLength.*value=.1") {
                    $riskFactors += "Weak Password Policy"
                }
                if ($gpoXml -match "ScheduledTasks.*RunAs.*SYSTEM") {
                    $riskFactors += "SYSTEM Scheduled Tasks"
                }
                if ($gpoXml -match "SoftwareInstallation") {
                    $riskFactors += "Software Installation Rights"
                }
                if ($gpoXml -match "Scripts.*Startup|Scripts.*Logon") {
                    $riskFactors += "Startup/Logon Scripts"
                }
                
                if ($riskFactors.Count -gt 0) {
                    $securityGPOs += [PSCustomObject]@{
                        GPOName = $gpo.DisplayName
                        GPOID = $gpo.Id
                        Created = "Security Analysis"
                        Modified = "Security Analysis"
                        Owner = "Security Analysis"
                        Status = "SECURITY RISK"
                        WMIFilter = "N/A"
                        ComputerVersion = "N/A"
                        UserVersion = "N/A"
                        Description = "Risk Factors: $($riskFactors -join ', ')"
                        Type = "Security Analysis"
                    }
                }
            }
            catch {
                # Skip GPOs we can't analyze
            }
        }
        
        $results += $securityGPOs
        Write-Host "[+] Identified $($securityGPOs.Count) GPOs with potential security implications" -ForegroundColor Green
        
    } else {
        # Fallback enumeration without GroupPolicy module
        Write-Host "[*] Using limited AD enumeration for GPO discovery..." -ForegroundColor Yellow
        
        # Look for GPO containers in AD
        $gpoContainers = Get-ADObject -Filter "ObjectClass -eq 'groupPolicyContainer'" @domainParams -Properties *
        
        foreach ($container in $gpoContainers) {
            $results += [PSCustomObject]@{
                GPOName = $container.displayName
                GPOID = $container.Name
                Created = $container.Created.ToString("yyyy-MM-dd HH:mm:ss")
                Modified = $container.Modified.ToString("yyyy-MM-dd HH:mm:ss")
                Owner = "Unknown"
                Status = "Found via AD"
                WMIFilter = "Unknown"
                ComputerVersion = $container.versionNumber
                UserVersion = "Unknown"
                Description = $container.DistinguishedName
                Type = "AD Container"
            }
        }
        
        Write-Host "[+] Found $($gpoContainers.Count) GPO containers via AD enumeration" -ForegroundColor Green
    }
    
    # Output summary
    Write-Host ""
    Write-Host "Group Policy Discovery Summary:" -ForegroundColor Cyan
    Write-Host "- Domain: $($currentDomain.DNSRoot)" -ForegroundColor White
    Write-Host "- Total GPO Entries: $($results.Count)" -ForegroundColor White
    Write-Host "- Security Risk GPOs: $(($results | Where-Object {$_.Status -eq 'SECURITY RISK'}).Count)" -ForegroundColor White
    Write-Host "- GPO Module Available: $gpModuleAvailable" -ForegroundColor White
    Write-Host "- Timestamp: $timestamp" -ForegroundColor White
    
    return $results
    
} catch {
    Write-Host "[!] Group Policy discovery failed: $($_.Exception.Message)" -ForegroundColor Red
    
    # Ultimate fallback
    try {
        Write-Host "[*] Attempting registry-based GPO enumeration..." -ForegroundColor Yellow
        
        $regGPOs = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\History" -ErrorAction SilentlyContinue
        
        foreach ($regGPO in $regGPOs) {
            $results += [PSCustomObject]@{
                GPOName = $regGPO.PSChildName
                GPOID = $regGPO.PSChildName
                Created = "Unknown"
                Modified = "Unknown"
                Owner = "Unknown"
                Status = "Registry Fallback"
                WMIFilter = "Unknown"
                ComputerVersion = "Unknown"
                UserVersion = "Unknown"
                Description = "Found in local registry"
                Type = "Registry Entry"
            }
        }
        
        Write-Host "[+] Registry fallback found $($regGPOs.Count) GPO entries" -ForegroundColor Green
        return $results
        
    } catch {
        Write-Host "[!] All enumeration methods failed" -ForegroundColor Red
        return @()
    }
}