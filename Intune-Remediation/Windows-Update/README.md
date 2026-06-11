# Intune Windows Update Remediation Script

This package contains an Intune Proactive Remediation script pair for forcing Windows Updates on Windows devices.

## Overview

- **Detection Script**: Checks if there are pending Windows Updates
- **Remediation Script**: Downloads and installs all pending updates, forcing a restart if required

## Files

1. `Detection-WindowsUpdate.ps1` - Detects pending updates
2. `Remediation-WindowsUpdate.ps1` - Installs updates and forces restart

## How It Works

### Detection Script
- Queries Windows Update COM object for pending updates
- Returns exit code `0` if device is compliant (no updates pending)
- Returns exit code `1` if device is non-compliant (updates pending)

### Remediation Script
- Downloads all pending Windows Updates
- Installs all updates without user interaction
- Forces an immediate restart if required (30-second delay with notification)
- Logs all actions for troubleshooting

## Deployment in Intune

### Prerequisites
- Devices must be running Windows 10/11
- Devices must have internet connectivity
- Windows Update service must be running
- PowerShell execution policy must allow script execution

### Steps to Deploy

1. **In Microsoft Intune Admin Center:**
   - Navigate to: **Devices** → **Remediation scripts** → **Create**

2. **Basic Information:**
   - Name: `Force Windows Update`
   - Description: `Detects and installs pending Windows Updates`

3. **Settings:**
   - **Detection script:** Copy contents of `Detection-WindowsUpdate.ps1`
   - **Remediation script:** Copy contents of `Remediation-WindowsUpdate.ps1`
   - **Run this script using the logged-in credentials:** `No` (runs as SYSTEM)
   - **Enforce script signature check:** `No`
   - **Run script in 64-bit PowerShell:** `Yes`

4. **Scope Tags:**
   - Select appropriate scope tags for your organization

5. **Assignments:**
   - Select device groups or users to target
   - Recommended: All Windows 10/11 devices

6. **Schedule:**
   - Set remediation schedule (e.g., Daily, Weekly)
   - Recommended: Weekly or Daily

## Important Notes

⚠️ **Restart Behavior**
- The remediation script will force a restart 30 seconds after update installation
- Users have a 30-second warning before restart
- All unsaved work will be lost if not saved before restart

⚠️ **Execution Context**
- Scripts run as SYSTEM account (not user)
- No interactive prompts will be displayed to users
- Updates will install silently in background

⚠️ **Update Availability**
- Scripts will only install updates available from Windows Update servers
- Corporate/custom update sources are not supported by this script

## Monitoring

In Intune:
- Monitor remediation results in: **Devices** → **Remediation scripts** → Select your script
- View device compliance status
- Check remediation history for individual devices

## Troubleshooting

### Script Fails on Specific Devices
- Check that Windows Update service is running
- Verify device has internet connectivity
- Check device logs: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\`

### Updates Not Installing
- Verify Windows Update service is not disabled
- Check for Group Policy conflicts
- Review Windows Update logs: `Event Viewer → Windows Logs → System`

### Restart Issues
- Some enterprise environments may block forced restarts
- Consider scheduling during maintenance windows
- Communicate restart policy to users

## Log Locations

- Intune Management Extension Logs: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\`
- Windows Update Logs: `C:\Windows\Logs\WindowsUpdate\`

## License

Modify as needed for your organization's requirements.
