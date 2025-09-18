# IT AnyDesk Remote Support Deployment

This package provides automated AnyDesk deployment for IT remote support with administrator privileges.

## Files

- `IT_AnyDesk_Deployment.ps1` - Main PowerShell deployment script
- `Deploy_AnyDesk_IT.bat` - Simple double-click wrapper that handles admin elevation
- `README_IT_Deployment.md` - This documentation

## Quick Deployment

### Option 1: Double-Click Deployment
1. Double-click `Deploy_AnyDesk_IT.bat`
2. Click "Yes" when prompted for administrator privileges
3. Note the AnyDesk ID and password displayed

### Option 2: PowerShell Direct
```powershell
# Run as Administrator
.\IT_AnyDesk_Deployment.ps1 -OrganizationID "YourOrgID" -AdminPassword "YourPassword"
```

## Configuration

Edit the batch file or PowerShell script to customize:

```batch
set ORG_ID=YourOrgID           # Your organization identifier
set ADMIN_PASS=ITSupport2024!  # Remote access password
set WEBHOOK_URL=               # Optional: webhook for centralized logging
```

## Features

- **Silent Installation**: No user prompts during deployment
- **Administrator Privileges**: Full system access for IT troubleshooting
- **Embedded Configuration**: No external config files needed
- **Automatic Service Setup**: Starts with Windows, runs as system service
- **Comprehensive Logging**: Deployment logs saved to `C:\ProgramData\AnyDesk\IT_Deployment.log`
- **Windows 11 Compatible**: Handles UAC and modern Windows security

## Remote Access Capabilities

Once deployed, IT administrators can:
- Remote desktop with full admin privileges
- File transfer for tools and diagnostics
- System reboot capabilities
- UAC interaction for privileged operations
- Background operation (no user notification)

## Security Notes

- Configuration file protected with admin-only permissions
- Service runs under SYSTEM account
- All actions logged for audit trail
- Password should be organization-specific and secure

## Uninstallation

To remove AnyDesk:
1. Uninstall via Windows Programs and Features
2. Delete `C:\ProgramData\AnyDesk\` folder
3. Remove AnyDesk service if still present

## Support

For IT deployment issues, check:
- `C:\ProgramData\AnyDesk\IT_Deployment.log` - Deployment log
- `C:\ProgramData\AnyDesk\ad.trace` - AnyDesk runtime log
- Windows Event Viewer - System and Application logs