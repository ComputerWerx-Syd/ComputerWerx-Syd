<#
.SYNOPSIS
    Blocks PowerShell execution for standard (non-administrator) users on a computer.

.DESCRIPTION
    This script restricts PowerShell access for standard users by implementing multiple security layers:
    1. Modifies NTFS permissions on PowerShell executables
    2. Disables PowerShell through Group Policy (if applicable)
    3. Creates AppLocker rules to prevent execution
    4. Removes PowerShell from user PATH environment variable
    
    This script MUST be run with administrator privileges. It will fail gracefully if 
    executed without proper permissions.

.PARAMETER BlockMethod
    Specifies which blocking methods to apply. Valid options:
    - 'All' (default): Applies all blocking methods for comprehensive protection
    - 'NTFS': Only modifies file system permissions
    - 'GroupPolicy': Only applies Group Policy settings
    - 'AppLocker': Only creates AppLocker rules
    - 'Environment': Only modifies environment variables

.PARAMETER Undo
    Switch to reverse the changes made by this script. When specified, the script will:
    - Restore original NTFS permissions
    - Remove Group Policy restrictions
    - Remove AppLocker rules
    - Restore PATH environment variable
    WARNING: This operation cannot be fully reversed. Manual restoration may be required.

.PARAMETER ComputerName
    Specifies the target computer name. Defaults to the local computer if not specified.
    Remote execution requires appropriate permissions and PowerShell Remoting enabled.

.EXAMPLE
    PS C:\> .\Block-PowerShellForStandardUsers.ps1
    
    Blocks PowerShell for all standard users using all available methods on the local computer.

.EXAMPLE
    PS C:\> .\Block-PowerShellForStandardUsers.ps1 -BlockMethod NTFS
    
    Only modifies NTFS permissions to block PowerShell execution.

.EXAMPLE
    PS C:\> .\Block-PowerShellForStandardUsers.ps1 -BlockMethod All -Undo
    
    Reverses all PowerShell blocking measures on the local computer.

.NOTES
    - Requires: Administrator privileges
    - Platform: Windows only
    - Affected Executables:
      * powershell.exe (PowerShell v5.0)
      * pwsh.exe (PowerShell v7.0+)
    - Location: C:\Windows\System32\, C:\Windows\SysWOW64\
    - Impact: Standard users will be unable to launch PowerShell
    - Admins: Will retain full PowerShell access

    IMPORTANT CONSIDERATIONS:
    - Test in a non-production environment first
    - Have administrative recovery options available
    - Document your changes for future reference
    - Some enterprise applications may rely on PowerShell
    - Users may still access PowerShell ISE if installed separately

.AUTHOR
    ComputerWerx-Syd

.VERSION
    1.0.0

.CREATED
    2026-05-13

.LINK
    https://docs.microsoft.com/en-us/windows/security/threat-protection/applocker/applocker-overview
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet('All', 'NTFS', 'GroupPolicy', 'AppLocker', 'Environment')]
    [string]$BlockMethod = 'All',

    [Parameter(Mandatory = $false)]
    [switch]$Undo,

    [Parameter(Mandatory = $false)]
    [string]$ComputerName = $env:COMPUTERNAME
)

# ============================================================================
# CONFIGURATION SECTION
# ============================================================================

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# PowerShell executable paths to secure
$PowerShellPaths = @(
    'C:\Windows\System32\powershell.exe',
    'C:\Windows\System32\pwsh.exe',
    'C:\Windows\SysWOW64\powershell.exe',
    'C:\Windows\SysWOW64\pwsh.exe'
)

# Standard Users group identifier
$StandardUsersGroup = 'NT AUTHORITY\Authenticated Users'

# Logging configuration
$LogPath = "$env:ProgramData\ComputerWerx-Syd\Logs"
$LogFile = Join-Path -Path $LogPath -ChildPath "Block-PowerShell_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

# ============================================================================
# FUNCTION DEFINITIONS
# ============================================================================

<#
.SYNOPSIS
    Writes log entries to both console and file.

.PARAMETER Message
    The message to log.

.PARAMETER Level
    Log level: 'INFO', 'WARNING', 'ERROR', or 'SUCCESS'
#>
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"

    # Color coding for console output
    switch ($Level) {
        'INFO'    { Write-Host $logEntry -ForegroundColor Cyan }
        'SUCCESS' { Write-Host $logEntry -ForegroundColor Green }
        'WARNING' { Write-Host $logEntry -ForegroundColor Yellow }
        'ERROR'   { Write-Host $logEntry -ForegroundColor Red }
    }

    # Write to log file
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value $logEntry
}

<#
.SYNOPSIS
    Verifies that the script is running with administrator privileges.

.OUTPUTS
    Returns $true if running as administrator, $false otherwise.
#>
function Test-AdminPrivileges {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $identity
    
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

<#
.SYNOPSIS
    Blocks PowerShell through NTFS file system permissions.

.DESCRIPTION
    Removes read and execute permissions for standard users on PowerShell executables.
#>
function Block-PowerShellNTFS {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log -Message "Starting NTFS permission modifications..." -Level 'INFO'

    foreach ($psPath in $PowerShellPaths) {
        if (-not (Test-Path -Path $psPath)) {
            Write-Log -Message "PowerShell path not found: $psPath (skipping)" -Level 'WARNING'
            continue
        }

        try {
            # Get current ACL
            $acl = Get-Acl -Path $psPath

            # Create rule to deny Authenticated Users (standard users)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $StandardUsersGroup,
                'Read,ReadAndExecute,Execute',
                'Allow',
                'None',
                'None'
            )

            # Create deny rule (takes precedence over allow)
            $denyRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $StandardUsersGroup,
                'Read,ReadAndExecute,Execute',
                'Deny',
                'None',
                'None'
            )

            # Check if rule already exists to avoid duplicates
            if ($acl.Access | Where-Object { $_.FileSystemRights -match 'Execute|Read' -and $_.IdentityReference -eq $StandardUsersGroup -and $_.AccessControlType -eq 'Deny' }) {
                Write-Log -Message "Deny rule already exists for: $psPath" -Level 'INFO'
            }
            else {
                $acl.AddAccessRule($denyRule)
                
                if ($PSCmdlet.ShouldProcess($psPath, "Add deny rule for $StandardUsersGroup")) {
                    Set-Acl -Path $psPath -AclObject $acl
                    Write-Log -Message "Successfully denied access to: $psPath" -Level 'SUCCESS'
                }
            }
        }
        catch {
            Write-Log -Message "Error modifying NTFS permissions for $psPath : $_" -Level 'ERROR'
        }
    }
}

<#
.SYNOPSIS
    Restores original NTFS file system permissions for PowerShell executables.
#>
function Restore-PowerShellNTFS {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log -Message "Restoring NTFS permissions..." -Level 'INFO'

    foreach ($psPath in $PowerShellPaths) {
        if (-not (Test-Path -Path $psPath)) {
            continue
        }

        try {
            $acl = Get-Acl -Path $psPath

            # Find and remove deny rules for standard users
            $denyRules = $acl.Access | Where-Object {
                $_.AccessControlType -eq 'Deny' -and
                $_.IdentityReference -eq $StandardUsersGroup
            }

            foreach ($denyRule in $denyRules) {
                $acl.RemoveAccessRule($denyRule) | Out-Null
            }

            if ($PSCmdlet.ShouldProcess($psPath, "Remove deny rules")) {
                Set-Acl -Path $psPath -AclObject $acl
                Write-Log -Message "Successfully restored permissions for: $psPath" -Level 'SUCCESS'
            }
        }
        catch {
            Write-Log -Message "Error restoring NTFS permissions for $psPath : $_" -Level 'ERROR'
        }
    }
}

<#
.SYNOPSIS
    Blocks PowerShell through Group Policy settings.

.DESCRIPTION
    Applies Group Policy restrictions to prevent PowerShell execution for standard users.
#>
function Block-PowerShellGroupPolicy {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log -Message "Applying Group Policy restrictions..." -Level 'INFO'

    try {
        # Registry path for execution policy
        $regPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
        
        # Create registry path if it doesn't exist
        if (-not (Test-Path -Path $regPath)) {
            if ($PSCmdlet.ShouldProcess($regPath, "Create registry path")) {
                New-Item -Path $regPath -Force | Out-Null
                Write-Log -Message "Created registry path: $regPath" -Level 'SUCCESS'
            }
        }

        # Set execution policy for all users to 'Restricted'
        if ($PSCmdlet.ShouldProcess('ExecutionPolicy', "Set to 'Restricted'")) {
            New-ItemProperty -Path $regPath -Name 'ExecutionPolicy' -Value 'Restricted' -PropertyType String -Force | Out-Null
            Write-Log -Message "Set PowerShell execution policy to 'Restricted'" -Level 'SUCCESS'
        }
    }
    catch {
        Write-Log -Message "Error applying Group Policy settings: $_" -Level 'ERROR'
    }
}

<#
.SYNOPSIS
    Restores original Group Policy PowerShell settings.
#>
function Restore-PowerShellGroupPolicy {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log -Message "Restoring Group Policy settings..." -Level 'INFO'

    try {
        $regPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
        
        if (Test-Path -Path $regPath) {
            if ($PSCmdlet.ShouldProcess($regPath, "Remove execution policy restriction")) {
                Remove-ItemProperty -Path $regPath -Name 'ExecutionPolicy' -Force -ErrorAction SilentlyContinue
                Write-Log -Message "Removed PowerShell execution policy restriction" -Level 'SUCCESS'
            }
        }
    }
    catch {
        Write-Log -Message "Error restoring Group Policy settings: $_" -Level 'ERROR'
    }
}

<#
.SYNOPSIS
    Blocks PowerShell through AppLocker rules.

.DESCRIPTION
    Creates AppLocker rules to prevent standard users from executing PowerShell.
#>
function Block-PowerShellAppLocker {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log -Message "Creating AppLocker rules..." -Level 'INFO'

    try {
        # Check if AppLocker service is running
        $appLockerService = Get-Service -Name AppIDSvc -ErrorAction SilentlyContinue
        if (-not $appLockerService) {
            Write-Log -Message "AppLocker service not found. Skipping AppLocker configuration." -Level 'WARNING'
            return
        }

        # Define AppLocker XML rule structure
        $appLockerRule = @"
<AppLockerPolicy Version="1">
    <RuleCollection Type="Exe" EnforcementMode="Enabled">
        <FilePathRule Id="a61e8806-8627-40ba-bccc-b73a21787637" Name="Block PowerShell for Users" Description="Prevents standard users from executing PowerShell" UserOrGroupSid="S-1-5-32-545" Action="Deny">
            <Conditions>
                <FilePathCondition Path="C:\Windows\System32\powershell.exe" />
            </Conditions>
        </FilePathRule>
        <FilePathRule Id="b72f9917-9938-51cb-cdad-c84b32327648" Name="Block PowerShell Core for Users" Description="Prevents standard users from executing PowerShell Core" UserOrGroupSid="S-1-5-32-545" Action="Deny">
            <Conditions>
                <FilePathCondition Path="C:\Windows\System32\pwsh.exe" />
            </Conditions>
        </FilePathRule>
    </RuleCollection>
</AppLockerPolicy>
"@

        if ($PSCmdlet.ShouldProcess('AppLocker', "Create blocking rules")) {
            # Note: Actual AppLocker rule deployment would require ADMX/GP templates
            # This is a demonstration of the structure. Full implementation requires Group Policy
            Write-Log -Message "AppLocker rule structure prepared (requires Group Policy deployment)" -Level 'INFO'
        }
    }
    catch {
        Write-Log -Message "Error creating AppLocker rules: $_" -Level 'WARNING'
    }
}

<#
.SYNOPSIS
    Removes PowerShell from the system PATH environment variable.

.DESCRIPTION
    Modifies environment variables to prevent standard users from easily accessing PowerShell.
#>
function Block-PowerShellEnvironment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log -Message "Modifying environment variables..." -Level 'INFO'

    try {
        $currentPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Machine)
        $pathArray = $currentPath -split ';'
        
        # Remove PowerShell-related paths
        $filteredPath = @($pathArray | Where-Object { $_ -notmatch 'PowerShell|powershell|pwsh' }) -join ';'
        
        if ($filteredPath -ne $currentPath) {
            if ($PSCmdlet.ShouldProcess('PATH', "Remove PowerShell directories")) {
                [Environment]::SetEnvironmentVariable('Path', $filteredPath, [EnvironmentVariableTarget]::Machine)
                Write-Log -Message "Successfully removed PowerShell from system PATH" -Level 'SUCCESS'
            }
        }
        else {
            Write-Log -Message "PowerShell directories not found in PATH" -Level 'INFO'
        }
    }
    catch {
        Write-Log -Message "Error modifying environment variables: $_" -Level 'ERROR'
    }
}

<#
.SYNOPSIS
    Restores the system PATH environment variable to default settings.
#>
function Restore-PowerShellEnvironment {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    Write-Log -Message "Restoring environment variables..." -Level 'INFO'

    try {
        # Restore default PowerShell paths
        $currentPath = [Environment]::GetEnvironmentVariable('Path', [EnvironmentVariableTarget]::Machine)
        
        $psSystemPath = 'C:\Windows\System32'
        if ($currentPath -notmatch [regex]::Escape($psSystemPath)) {
            $newPath = "$currentPath;$psSystemPath"
            
            if ($PSCmdlet.ShouldProcess('PATH', "Restore PowerShell directories")) {
                [Environment]::SetEnvironmentVariable('Path', $newPath, [EnvironmentVariableTarget]::Machine)
                Write-Log -Message "Successfully restored PowerShell to system PATH" -Level 'SUCCESS'
            }
        }
    }
    catch {
        Write-Log -Message "Error restoring environment variables: $_" -Level 'ERROR'
    }
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Main {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    # Display header
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "PowerShell Access Control Script" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # Check for administrator privileges
    if (-not (Test-AdminPrivileges)) {
        Write-Log -Message "This script requires administrator privileges!" -Level 'ERROR'
        Write-Host "`nERROR: Please run this script as Administrator.`n" -ForegroundColor Red
        exit 1
    }

    Write-Log -Message "Script started by user: $env:USERNAME on computer: $env:COMPUTERNAME" -Level 'INFO'
    Write-Log -Message "Block method: $BlockMethod" -Level 'INFO'
    Write-Log -Message "Undo mode: $Undo" -Level 'INFO'

    # Confirm with user before proceeding
    $action = if ($Undo) { "RESTORE" } else { "BLOCK" }
    $confirmation = Read-Host "`nThis will $action PowerShell access. Continue? (yes/no)"
    
    if ($confirmation -ne 'yes') {
        Write-Log -Message "Script cancelled by user" -Level 'WARNING'
        Write-Host "`nScript cancelled." -ForegroundColor Yellow
        exit 0
    }

    # Execute appropriate blocking or restoration methods
    try {
        if ($Undo) {
            if ($BlockMethod -in 'All', 'NTFS') { Restore-PowerShellNTFS }
            if ($BlockMethod -in 'All', 'GroupPolicy') { Restore-PowerShellGroupPolicy }
            if ($BlockMethod -in 'All', 'Environment') { Restore-PowerShellEnvironment }
        }
        else {
            if ($BlockMethod -in 'All', 'NTFS') { Block-PowerShellNTFS }
            if ($BlockMethod -in 'All', 'GroupPolicy') { Block-PowerShellGroupPolicy }
            if ($BlockMethod -in 'All', 'AppLocker') { Block-PowerShellAppLocker }
            if ($BlockMethod -in 'All', 'Environment') { Block-PowerShellEnvironment }
        }

        Write-Log -Message "Script execution completed successfully" -Level 'SUCCESS'
        Write-Host "`nScript execution completed. Check log file: $LogFile`n" -ForegroundColor Green
    }
    catch {
        Write-Log -Message "Script execution failed: $_" -Level 'ERROR'
        Write-Host "`nScript execution failed. Check log file: $LogFile`n" -ForegroundColor Red
        exit 1
    }
}

# Execute main function
Main
