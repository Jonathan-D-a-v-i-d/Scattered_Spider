@{
    # Module manifest for Victim Host Recon Module
    
    RootModule = 'VictimHostRecon.psm1'
    ModuleVersion = '1.0.0'
    GUID = '12345678-1234-5678-9012-123456789012'
    
    Author = 'Security Research Team'
    CompanyName = 'Security Research Lab'
    Copyright = '(c) Security Research. All rights reserved.'
    
    Description = 'PowerShell module for victim host reconnaissance and security research simulation based on MITRE ATT&CK framework'
    
    PowerShellVersion = '5.1'
    
    # Functions to export from this module
    FunctionsToExport = @(
        'Invoke-AccountDiscovery',
        'Invoke-NetworkServiceDiscovery',
        'Invoke-ProcessDiscovery',
        'Invoke-SoftwareDiscovery',
        'Invoke-SystemInfoDiscovery',
        'Invoke-FullReconnaissance',
        'Get-ReconResults'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @(
        'Run-Recon',
        'Get-HostInfo',
        'Start-Discovery'
    )
    
    # Private data
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Reconnaissance', 'MITRE', 'Research', 'Discovery')
            LicenseUri = ''
            ProjectUri = 'https://github.com/Jonathan-D-a-v-i-d/Scattered_Spider'
            ReleaseNotes = 'Initial release of Victim Host reconnaissance module for security research'
        }
    }
}