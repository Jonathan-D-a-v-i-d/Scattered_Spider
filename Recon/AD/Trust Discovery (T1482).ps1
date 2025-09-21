# === Active Directory Trust Discovery (T1482) ===
# Enumerates domain trusts for potential lateral movement paths
# Maps to MITRE ATT&CK T1482 - Domain Trust Discovery

param(
    [string]$Domain = "",
    [string]$Server = "",
    [switch]$Detailed = $false
)

$results = @()
$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC"

Write-Host "[*] Starting Trust Discovery (T1482)..." -ForegroundColor Cyan

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
    
    # Get domain trusts
    Write-Host "[*] Enumerating domain trusts..." -ForegroundColor Yellow
    $trusts = Get-ADTrust -Filter * @domainParams
    
    foreach ($trust in $trusts) {
        try {
            $trustDirection = switch ($trust.Direction) {
                "Inbound" { "Incoming Trust" }
                "Outbound" { "Outgoing Trust" }
                "Bidirectional" { "Two-Way Trust" }
                default { $trust.Direction }
            }
            
            $trustType = switch ($trust.TrustType) {
                "TreeRoot" { "Tree Root" }
                "ParentChild" { "Parent-Child" }
                "External" { "External" }
                "Forest" { "Forest" }
                "ForestTransitive" { "Forest Transitive" }
                "Unknown" { "Unknown" }
                default { $trust.TrustType }
            }
            
            $trustAttributes = @()
            if ($trust.TrustAttributes -band 0x0001) { $trustAttributes += "Non-Transitive" }
            if ($trust.TrustAttributes -band 0x0002) { $trustAttributes += "Uplevel-Only" }
            if ($trust.TrustAttributes -band 0x0004) { $trustAttributes += "Quarantined" }
            if ($trust.TrustAttributes -band 0x0008) { $trustAttributes += "Forest-Transitive" }
            if ($trust.TrustAttributes -band 0x0010) { $trustAttributes += "Cross-Organization" }
            if ($trust.TrustAttributes -band 0x0020) { $trustAttributes += "Within-Forest" }
            if ($trust.TrustAttributes -band 0x0040) { $trustAttributes += "Treat-As-External" }
            
            $results += [PSCustomObject]@{
                TrustTarget = $trust.Target
                TrustSource = $trust.Source
                TrustDirection = $trustDirection
                TrustType = $trustType
                TrustAttributes = if($trustAttributes) { $trustAttributes -join ", " } else { "None" }
                Created = $trust.Created.ToString("yyyy-MM-dd HH:mm:ss")
                Modified = $trust.Modified.ToString("yyyy-MM-dd HH:mm:ss")
                SIDFilteringEnabled = $trust.SIDFilteringEnabled
                DisallowTransitivity = $trust.DisallowTransitivity
                SelectiveAuthentication = $trust.SelectiveAuthentication
                TGTDelegation = $trust.TGTDelegation
                DistinguishedName = $trust.DistinguishedName
                Notes = "Domain Trust"
            }
            
            # Get detailed information if requested
            if ($Detailed) {
                try {
                    # Try to get information about the trusted domain
                    $trustedDomainInfo = Get-ADDomain -Identity $trust.Target -ErrorAction SilentlyContinue
                    if ($trustedDomainInfo) {
                        $results += [PSCustomObject]@{
                            TrustTarget = "$($trust.Target) (Details)"
                            TrustSource = $currentDomain.DNSRoot
                            TrustDirection = "Domain Information"
                            TrustType = "Forest Level: $($trustedDomainInfo.ForestMode)"
                            TrustAttributes = "Domain Level: $($trustedDomainInfo.DomainMode)"
                            Created = $trustedDomainInfo.DomainSID.ToString()
                            Modified = "N/A"
                            SIDFilteringEnabled = "N/A"
                            DisallowTransitivity = "N/A"
                            SelectiveAuthentication = "N/A"
                            TGTDelegation = "N/A"
                            DistinguishedName = $trustedDomainInfo.DistinguishedName
                            Notes = "Trusted Domain Details"
                        }
                    }
                }
                catch {
                    # Could not get detailed info about trusted domain
                }
            }
        }
        catch {
            Write-Host "[!] Could not process trust: $($trust.Target)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "[+] Found $($trusts.Count) domain trusts" -ForegroundColor Green
    
    # Get forest information
    Write-Host "[*] Enumerating forest information..." -ForegroundColor Yellow
    
    try {
        $forest = Get-ADForest @domainParams
        
        $results += [PSCustomObject]@{
            TrustTarget = $forest.Name
            TrustSource = "Current Forest"
            TrustDirection = "Forest Root"
            TrustType = "Forest Mode: $($forest.ForestMode)"
            TrustAttributes = "Schema Master: $($forest.SchemaMaster)"
            Created = "Domain Naming Master: $($forest.DomainNamingMaster)"
            Modified = "Sites: $($forest.Sites.Count)"
            SIDFilteringEnabled = "Domains: $($forest.Domains.Count)"
            DisallowTransitivity = "Global Catalogs: $($forest.GlobalCatalogs.Count)"
            SelectiveAuthentication = "N/A"
            TGTDelegation = "N/A"
            DistinguishedName = $forest.PartitionsContainer
            Notes = "Forest Information"
        }
        
        # List all domains in forest
        foreach ($forestDomain in $forest.Domains) {
            if ($forestDomain -ne $currentDomain.DNSRoot) {
                $results += [PSCustomObject]@{
                    TrustTarget = $forestDomain
                    TrustSource = $currentDomain.DNSRoot
                    TrustDirection = "Forest Domain"
                    TrustType = "Same Forest"
                    TrustAttributes = "Implicit Trust"
                    Created = "N/A"
                    Modified = "N/A"
                    SIDFilteringEnabled = "No"
                    DisallowTransitivity = "No"
                    SelectiveAuthentication = "No"
                    TGTDelegation = "Yes"
                    DistinguishedName = "N/A"
                    Notes = "Forest Domain"
                }
            }
        }
        
        Write-Host "[+] Forest contains $($forest.Domains.Count) domains" -ForegroundColor Green
    }
    catch {
        Write-Host "[!] Could not enumerate forest information" -ForegroundColor Yellow
    }
    
    # Analyze trust security implications
    Write-Host "[*] Analyzing trust security implications..." -ForegroundColor Yellow
    
    $securityTrusts = @()
    foreach ($trust in $trusts) {
        $riskFactors = @()
        
        if ($trust.TrustType -eq "External") {
            $riskFactors += "External Domain"
        }
        if (-not $trust.SIDFilteringEnabled) {
            $riskFactors += "SID Filtering Disabled"
        }
        if ($trust.SelectiveAuthentication -eq $false) {
            $riskFactors += "Selective Authentication Disabled"
        }
        if ($trust.Direction -eq "Inbound" -or $trust.Direction -eq "Bidirectional") {
            $riskFactors += "Allows Inbound Access"
        }
        
        if ($riskFactors.Count -gt 0) {
            $securityTrusts += [PSCustomObject]@{
                TrustTarget = $trust.Target
                TrustSource = "Security Analysis"
                TrustDirection = "SECURITY RISK"
                TrustType = $trust.TrustType
                TrustAttributes = "Risk Factors: $($riskFactors -join ', ')"
                Created = "Security Analysis"
                Modified = "Security Analysis"
                SIDFilteringEnabled = $trust.SIDFilteringEnabled
                DisallowTransitivity = $trust.DisallowTransitivity
                SelectiveAuthentication = $trust.SelectiveAuthentication
                TGTDelegation = $trust.TGTDelegation
                DistinguishedName = $trust.DistinguishedName
                Notes = "Trust Security Analysis"
            }
        }
    }
    
    $results += $securityTrusts
    Write-Host "[+] Identified $($securityTrusts.Count) trusts with potential security implications" -ForegroundColor Green
    
    # Output summary
    Write-Host ""
    Write-Host "Trust Discovery Summary:" -ForegroundColor Cyan
    Write-Host "- Domain: $($currentDomain.DNSRoot)" -ForegroundColor White
    Write-Host "- Total Trust Entries: $($results.Count)" -ForegroundColor White
    Write-Host "- Domain Trusts: $($trusts.Count)" -ForegroundColor White
    Write-Host "- Security Risk Trusts: $($securityTrusts.Count)" -ForegroundColor White
    Write-Host "- Timestamp: $timestamp" -ForegroundColor White
    
    return $results
    
} catch {
    Write-Host "[!] Trust discovery failed: $($_.Exception.Message)" -ForegroundColor Red
    
    # Fallback using nltest
    Write-Host "[*] Attempting fallback enumeration..." -ForegroundColor Yellow
    
    try {
        $nltestResult = & nltest.exe /domain_trusts 2>$null
        if ($LASTEXITCODE -eq 0) {
            $trustLines = $nltestResult | Select-String "^\s*\d+:" | ForEach-Object { $_.Line.Trim() }
            
            foreach ($trustLine in $trustLines) {
                if ($trustLine -match "^\d+:\s+(.+?)\s+\((.+?)\)") {
                    $trustName = $matches[1]
                    $trustInfo = $matches[2]
                    
                    $results += [PSCustomObject]@{
                        TrustTarget = $trustName
                        TrustSource = $env:USERDNSDOMAIN
                        TrustDirection = "Unknown"
                        TrustType = "Unknown"
                        TrustAttributes = $trustInfo
                        Created = "Unknown"
                        Modified = "Unknown"
                        SIDFilteringEnabled = "Unknown"
                        DisallowTransitivity = "Unknown"
                        SelectiveAuthentication = "Unknown"
                        TGTDelegation = "Unknown"
                        DistinguishedName = "Unknown"
                        Notes = "Fallback Enumeration"
                    }
                }
            }
            
            Write-Host "[+] Fallback enumeration found $($results.Count) trust entries" -ForegroundColor Green
            return $results
        } else {
            throw "Nltest enumeration also failed"
        }
    }
    catch {
        Write-Host "[!] All enumeration methods failed" -ForegroundColor Red
        return @()
    }
}