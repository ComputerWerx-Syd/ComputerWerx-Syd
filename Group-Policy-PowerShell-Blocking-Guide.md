# Block PowerShell Scripts via Domain Group Policy - Step-by-Step Guide

## Overview
This guide provides detailed instructions to block PowerShell script execution for standard users across your domain using Group Policy. This prevents unauthorized script execution while maintaining administrator access.

---

## Prerequisites

- **Domain Admin Rights**: You must have Domain Administrator privileges
- **Group Policy Management Console (GPMC)**: Should be installed on your domain controller or admin workstation
- **Windows Server 2012 R2 or later**: For the domain
- **Target Computers**: Windows 7 SP1 or later (Windows 10/11 recommended)

### Install GPMC (if needed)
```powershell
# On Windows Server
Install-WindowsFeature -Name GPMC

# On Windows 10/11 Client
# Settings > Apps > Apps & features > Optional features > Add a feature
# Search for "RSAT: Group Policy Management Tools"
```

---

## Method 1: PowerShell Execution Policy via Group Policy (Recommended for Quick Deployment)

### Step 1: Open Group Policy Management Console

1. **On a domain-joined computer with admin rights**:
   - Press `Win + R`
   - Type `gpmc.msc`
   - Press Enter

2. **Alternatively, via command line**:
   ```powershell
   gpmc.msc
   ```

### Step 2: Create or Select a Group Policy Object (GPO)

**Option A: Create a New GPO**

1. Right-click on **Group Policy Objects** in the left pane
2. Click **New**
3. Enter a descriptive name: `"Block PowerShell Execution - Standard Users"`
4. Click **OK**

**Option B: Link to an Existing Organizational Unit (OU)**

1. Expand your domain in the left pane
2. Right-click on the target **OU** (e.g., "Standard Users")
3. Click **Create a GPO in this domain, and Link it here...**
4. Name it: `"Block PowerShell Execution - Standard Users"`
5. Click **OK**

### Step 3: Edit the Group Policy Object

1. Right-click the newly created GPO
2. Click **Edit**
3. The **Group Policy Management Editor** opens

### Step 4: Navigate to PowerShell Execution Policy Setting

**Path in Group Policy Editor:**

```
Computer Configuration
  → Administrative Templates
    → Windows Components
      → Windows PowerShell
```

### Step 5: Configure the Execution Policy

1. Look for **"Turn on PowerShell Script Block Logging"** (optional, for audit trail)
   - Set to **Enabled**
   - Select: **Log script block invocation start / stop events**
   - Click **OK**

2. Find **"Set the default source for Update-Help"** (related security)
   - Set to **Enabled**

3. **Most Important**: Find **"Turn on Script Execution"**
   - Set to **Enabled**
   - Policy options:
     - **Allow local scripts and remote signed scripts** (Recommended)
     - **Allow only signed scripts** (Most restrictive)
     - **Allow all scripts** (Not recommended for security)
   
   **For blocking standard users, select**: **"Allow only signed scripts"** or **"Disabled"**

### Step 6: Configure User-Level Settings (Alternative Path)

1. Navigate to:
   ```
   User Configuration
     → Administrative Templates
       → Windows Components
         → Windows PowerShell
   ```

2. Set **"Execution Policy"** to:
   - **Restricted** (blocks all scripts)
   - **AllSigned** (requires signed scripts only)

### Step 7: Link the GPO to Target OUs

1. In GPMC, right-click the target **OU** (e.g., "Standard Users")
2. Click **Link an Existing GPO**
3. Select your new GPO: `"Block PowerShell Execution - Standard Users"`
4. Click **OK**

### Step 8: Verify GPO Permissions

1. Right-click the GPO
2. Click **Delegation**
3. Ensure:
   - **Domain Admins**: Full Control ✓
   - **Authenticated Users**: Read permission ✓
   - **Standard Users**: Do NOT have "Apply Group Policy" permission

**To remove "Apply Group Policy" for standard users:**

1. Click **Advanced**
2. Select **Authenticated Users**
3. Click **Edit**
4. Uncheck **"Apply Group Policy"**
5. Click **OK**
6. Click **OK** again

---

## Method 2: AppLocker Policy (Enterprise-Grade, Requires Windows Server 2012+)

### Step 1: Verify AppLocker Service Status

On domain computers, ensure the AppLocker service will start:

```powershell
Set-Service -Name AppIDSvc -StartupType Automatic
Start-Service -Name AppIDSvc
```

### Step 2: Create AppLocker GPO

1. Open **GPMC.msc**
2. Create a new GPO: `"Block PowerShell - AppLocker"`

### Step 3: Configure AppLocker Settings

1. Right-click the GPO and click **Edit**

2. Navigate to:
   ```
   Computer Configuration
     → Windows Settings
       → Security Settings
         → Application Control Policies
           → AppLocker
   ```

3. Right-click **Executable Rules** and click **Create Default Rules**
   - This creates allow rules for administrators and system

4. Right-click **Executable Rules** again and click **Create New Rule**

5. **Create Deny Rule for PowerShell**:
   - **Rule Type**: Executable Rules
   - **Action**: Deny
   - **User**: Everyone (or Authenticated Users for standard users)
   - **Path**: `C:\Windows\System32\powershell.exe`
   - **Click OK**

6. **Repeat for 64-bit PowerShell**:
   - **Path**: `C:\Windows\SysWOW64\powershell.exe`

7. **Repeat for PowerShell 7+**:
   - **Path**: `C:\Program Files\PowerShell\*\pwsh.exe`
   - **Path**: `C:\Program Files (x86)\PowerShell\*\pwsh.exe`

### Step 4: Enable AppLocker Enforcement

1. Right-click **AppLocker** in the left pane
2. Click **Properties**
3. For **Executable rules**, select **Enforce rules**
4. Click **OK**

### Step 5: Configure Audit Logging

1. Still in AppLocker properties
2. Check **"Audit only"** (optional, to test before enforcement)
3. Click **OK** to apply

### Step 6: Link AppLocker GPO to OUs

1. In GPMC, right-click target **OU** (e.g., "Standard Users")
2. Click **Link an Existing GPO**
3. Select `"Block PowerShell - AppLocker"`
4. Click **OK**

---

## Method 3: Software Restriction Policies (Legacy, for older Windows versions)

### Step 1: Open Group Policy Editor

```
Computer Configuration
  → Windows Settings
    → Security Settings
      → Software Restriction Policies
```

### Step 2: Create Software Restriction Policy

1. Right-click **Software Restriction Policies**
2. Click **New Software Restriction Policies**

### Step 3: Create Path Rule

1. Right-click **Path Rules**
2. Click **New Path Rule**
3. Configure:
   - **Path**: `C:\Windows\System32\powershell.exe`
   - **Security Level**: **Unrestricted** (default)
   - Apply rule for: **All users except administrators**
   - Click **OK**

4. Repeat for other PowerShell paths:
   - `C:\Windows\SysWOW64\powershell.exe`
   - `%ProgramFiles%\PowerShell\*\pwsh.exe`

---

## Testing & Validation

### Test 1: Force Group Policy Update

**On a domain-joined computer**, run as Administrator:

```powershell
# Force immediate GPO refresh
gpupdate /force

# Check applied policies
gpresult /h report.html
# Opens report.html showing all applied policies
```

### Test 2: Verify PowerShell Execution Policy

As a **standard user**:

```powershell
# Check current execution policy
Get-ExecutionPolicy

# Expected output: Restricted or AllSigned
```

### Test 3: Try Running a Script

As a **standard user**:

```powershell
# Create test script
@"
Write-Host "This script is running"
"@ | Out-File C:\test.ps1

# Try to execute
C:\test.ps1

# Expected: Error message - "scripts are disabled on this system"
```

### Test 4: Verify Admin Access (Should Still Work)

As an **administrator**:

```powershell
# Should execute without issues
C:\test.ps1
```

### Test 5: Check Event Logs

Navigate to:

```
Event Viewer
  → Windows Logs
    → Application

# Filter by Source: PowerShell
```

Look for Event IDs:
- **400**: Engine state is changed from Available to Stopped
- **403**: PowerShell console is starting up
- **600**: Provider "Variable" is Started

---

## Troubleshooting

### Issue 1: GPO Not Applying

**Solution:**
```powershell
# Clear AppID cache
Remove-Item -Path "C:\ProgramData\AppID" -Recurse -Force -ErrorAction SilentlyContinue

# Restart AppID service
Restart-Service -Name AppIDSvc

# Force GPO update
gpupdate /force /sync
```

### Issue 2: PowerShell ISE Still Works

**Additional configuration needed:**

1. In Group Policy Editor, also block:
   ```
   C:\Windows\System32\ise.exe
   C:\Windows\SysWOW64\ise.exe
   ```

2. Or add AppLocker rule for ISE

### Issue 3: Scripts Still Execute After Policy Applied

1. **Verify GPO linked correctly**:
   ```powershell
   gpresult /scope:user /h user_report.html
   gpresult /scope:computer /h computer_report.html
   ```

2. **Check GPO blocking status**:
   - In GPMC, right-click the OU
   - Click **Properties**
   - Ensure **"Group Policy inheritance is blocked"** is NOT checked

3. **Restart computer**:
   ```powershell
   Restart-Computer -Force
   ```

### Issue 4: Need to Exclude Specific Users/Groups

1. In GPMC, right-click the GPO
2. Click **Security Filtering**
3. Add trusted users/groups that should have access

---

## Rollback Instructions

### To Remove PowerShell Blocking via GPO:

```powershell
# Option 1: Delete the GPO entirely
# In GPMC:
# 1. Right-click the GPO
# 2. Click Delete
# 3. Confirm deletion

# Option 2: Unlink the GPO from OUs
# In GPMC:
# 1. Right-click the OU
# 2. Click "Link Existing GPO"
# 3. Uncheck the PowerShell blocking GPO

# Option 3: Reset execution policy
# On each computer, run as admin:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

# Force GPO update
gpupdate /force
```

---

## Best Practices

✅ **DO:**
- Test in a pilot OU before enterprise-wide deployment
- Maintain a list of approved users who need PowerShell access
- Monitor Event Viewer for blocked script attempts
- Document all policy changes with dates and reasons
- Review and update policies quarterly
- Exclude critical system services and scheduled tasks

❌ **DON'T:**
- Block PowerShell entirely on domain controllers
- Block PowerShell for service accounts that need it
- Deploy without testing first
- Forget to create exceptions for legitimate enterprise tools
- Block ISE without informing users
- Enable "Audit only" permanently - switch to enforcement after testing

---

## Monitoring & Auditing

### Enable Enhanced Logging

```powershell
# Run as administrator on domain computer

# Enable PowerShell operational log
$logName = "Microsoft-Windows-PowerShell/Operational"
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.IsEnabled = $true
$log.SaveChanges()

# Enable Analytic log (for detailed tracking)
$logName = "Microsoft-Windows-PowerShell/Analytic"
$log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
$log.IsEnabled = $true
$log.SaveChanges()
```

### Query Blocked Script Attempts

```powershell
# Get last 10 blocked script attempts
Get-EventLog -LogName Application -Source PowerShell -Newest 10 |
  Where-Object { $_.Message -match "script execution" }
```

---

## Summary Checklist

- [ ] Created/selected target OU for standard users
- [ ] Created new GPO for PowerShell blocking
- [ ] Configured execution policy (Restricted or AllSigned)
- [ ] Linked GPO to target OU
- [ ] Verified GPO permissions (standard users cannot apply)
- [ ] Tested on pilot computers with standard user account
- [ ] Verified admins can still run PowerShell
- [ ] Checked Event Viewer for blocked attempts
- [ ] Documented all changes
- [ ] Informed users about change
- [ ] Set up monitoring/auditing

---

## Additional Resources

- [Microsoft: PowerShell Group Policy Documentation](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies)
- [AppLocker Documentation](https://docs.microsoft.com/en-us/windows/security/threat-protection/applocker/applocker-overview)
- [Group Policy Management Best Practices](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/best-practices-for-user-rights-assignment)

---

**Last Updated**: 2026-05-15  
**Author**: ComputerWerx-Syd  
**Version**: 1.0
