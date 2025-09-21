@echo off
REM === IT AnyDesk Deployment Batch Wrapper ===
REM Double-click to deploy AnyDesk for IT remote support
REM Automatically requests admin privileges

echo ===============================================
echo       IT AnyDesk Remote Support Deployment
echo ===============================================
echo.
echo This will install AnyDesk with IT admin privileges
echo for remote troubleshooting support.
echo.

REM Check if running as admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo Running with administrator privileges...
echo.

REM Set organization-specific parameters
set ORG_ID=YourOrgID
set ADMIN_PASS=ITSupport2024!
set WEBHOOK_URL=

REM Run the PowerShell deployment script
powershell -ExecutionPolicy Bypass -Command "& '%~dp0IT_AnyDesk_Deployment.ps1' -OrganizationID '%ORG_ID%' -AdminPassword '%ADMIN_PASS%' -WebhookURL '%WEBHOOK_URL%'"

echo.
echo Deployment completed. Check the output above for AnyDesk ID.
echo.
pause