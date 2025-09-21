# Scattered Spider Attack Chain - Complete Workflow

## Overview
This repository simulates the complete Scattered Spider attack chain for security research and defensive training purposes.

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

### Full Chain Automation
- `Deploy_Complete_Chain.ps1` - Complete attack chain automation

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

## Quick Deployment Commands

### For IT Support (Social Engineering)
```powershell
# Email the zip file, user runs:
Deploy_AnyDesk_IT.bat
```

### For Security Research (Complete Chain)
```powershell
# Simulate full attack chain:
.\Deploy_Complete_Chain.ps1 -AutoRecon

# Or individual phases:
.\Deploy_VictimHostRecon.ps1    # Host reconnaissance
.\Deploy_ADRecon.ps1            # Domain reconnaissance
```

### For Manual Operations
```powershell
# Host reconnaissance:
Import-Module .\Recon\Host\VictimHostRecon.psm1 -Force
Run-Recon

# Domain reconnaissance:
Import-Module .\Recon\AD\ADRecon.psm1 -Force
Run-ADRecon

# Individual techniques:
Get-HostInfo                    # System info
Invoke-AccountDiscovery         # Local accounts
Invoke-DomainUserDiscovery      # Domain users
Invoke-ComputerDiscovery        # Domain computers
```

## Output and Results

All reconnaissance results are centralized in:
```
C:\Intel\Logs\
├── VictimHost_SystemInfoDiscovery.txt
├── VictimHost_AccountDiscovery.txt
├── VictimHost_ProcessDiscovery.txt
├── VictimHost_SoftwareDiscovery.txt
├── VictimHost_NetworkServiceDiscovery.txt
├── VictimHost_FileDirectoryDiscovery.txt
├── VictimHost_ReconSummary.txt
├── ADRecon_DomainUserDiscovery.txt
├── ADRecon_GroupPolicyDiscovery.txt
├── ADRecon_ComputerDiscovery.txt
├── ADRecon_TrustDiscovery.txt
└── ADRecon_ReconSummary.txt
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

### Comprehensive Reconnaissance
- **MITRE Mapped**: All techniques properly categorized (10 total techniques)
- **Modular Design**: Can execute individual techniques, module-level, or complete reconnaissance
- **Centralized Output**: Single location for all collected intelligence
- **Dual Scope**: Local host reconnaissance + Active Directory domain reconnaissance
- **RSAT Integration**: Automatic installation of required AD tools

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