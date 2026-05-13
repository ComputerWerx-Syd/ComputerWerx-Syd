<#
.SYNOPSIS
    Implements Attack Surface Reduction (ASR) rules on Windows 10 systems.

.DESCRIPTION
    This comprehensive script configures Attack Surface Reduction (ASR) rules to enhance security
    on Windows 10 systems. ASR rules help block suspicious behaviors and malware execution patterns
    while maintaining system functionality. The script includes:
    - Configuration of all major ASR rules
    - Logging and monitoring setup
    - Backup of current settings
    - Validation and verification of configurations
    - Error handling and rollback capabilities

.PARAMETER Mode
    Specifies the ASR configuration mode:
    - 'Block': Enforces all ASR rules (recommended for production)
    - 'Audit': Logs ASR violations without blocking (recommended for testing)
    - 'Disable': Disables all ASR rules (not recommended)

.PARAMETER BackupPath
    Path where current ASR configuration will be backed up before changes.
    Default: $env:USERPROFILE\Desktop\ASR_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json

.PARAMETER ExclusionPath
    Path containing files/folders to exclude from ASR monitoring.
    These paths will be added as ASR exclusions to prevent false positives.

.PARAMETER LogPath
    Path where ASR logs will be stored. Default: $env:SystemRoot\temp\ASR_Logs

.PARAMETER SkipBackup
    Switch to skip creating a backup of current settings.

.EXAMPLE
    .\ASR-Implementation.ps1 -Mode Block
    Configures all ASR rules in block mode.

.EXAMPLE
    .\ASR-Implementation.ps1 -Mode Audit -ExclusionPath "C:\Program Files\CustomApp"
    Configures ASR in audit mode with exclusions for a custom application.

.EXAMPLE
    .\ASR-Implementation.ps1 -Mode Block -SkipBackup
    Configures ASR rules without backing up current settings.

.NOTES
    Author: ComputerWerx-Syd
    Version: 1.0
    Requires: Windows 10 (Build 1903 or later)
    Requires: Administrator privileges
    Requires: Windows Defender to be active
    Last Modified: 2026-05-13

.LINK
    https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/attack-surface-reduction

#>

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, HelpMessage = "ASR configuration mode: Block, Audit, or Disable")]
    [ValidateSet("Block", "Audit", "Disable")]
    [string]$Mode = "Block",

    [Parameter(Mandatory = $false, HelpMessage = "Path to backup current ASR settings")]
    [string]$BackupPath = "$env:USERPROFILE\Desktop\ASR_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').json",

    [Parameter(Mandatory = $false, HelpMessage = "Path containing exclusions")]
    [string]$ExclusionPath,

    [Parameter(Mandatory = $false, HelpMessage = "Path to store ASR logs")]
    [string]$LogPath = "$env:SystemRoot\temp\ASR_Logs",

    [Parameter(Mandatory = $false)]
    [switch]$SkipBackup
)

#region Functions

<#
.SYNOPSIS
    Validates that the script is running with Administrator privileges.

.DESCRIPTION
    Checks if the current PowerShell session has Administrator privileges.
    Exits the script if run without elevation.

.OUTPUTS
    $true if running as Administrator, otherwise exits the script.
#>
function Test-AdminPrivileges {
    [CmdletBinding()]
    param()

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal $identity

    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "This script requires Administrator privileges. Please run PowerShell as Administrator."
        exit 1
    }
    Write-Host "✓ Administrator privileges confirmed." -ForegroundColor Green
}

<#
.SYNOPSIS
    Validates Windows 10 version compatibility.

.DESCRIPTION
    Checks that the system is running Windows 10 Build 1903 or later.
    ASR rules require this minimum version to function.

.OUTPUTS
    $true if system meets requirements, otherwise exits the script.
#>
function Test-WindowsVersion {
    [CmdletBinding()]
    param()

    $osVersion = [System.Environment]::OSVersion.Version
    $buildNumber = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildNumber).CurrentBuildNumber

    Write-Host "Detected OS: Windows $($osVersion.Major).$($osVersion.Minor) - Build $buildNumber"

    if ($osVersion.Major -ne 10) {
        Write-Error "This script requires Windows 10. Detected Windows $($osVersion.Major)."
        exit 1
    }

    if ($buildNumber -lt 1903) {
        Write-Error "This script requires Windows 10 Build 1903 or later. Detected Build $buildNumber."
        exit 1
    }

    Write-Host "✓ Windows version is compatible (Build $buildNumber)." -ForegroundColor Green
}

<#
.SYNOPSIS
    Validates that Windows Defender is installed and running.

.DESCRIPTION
    Checks if Windows Defender (Antimalware Service Executable) is installed and active.
    ASR rules require Windows Defender to be operational.

.OUTPUTS
    $true if Windows Defender is active, otherwise exits the script.
#>
function Test-DefenderStatus {
    [CmdletBinding()]
    param()

    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        if ($null -eq $defenderStatus) {
            Write-Error "Windows Defender is not installed or not responding."
            exit 1
        }

        Write-Host "✓ Windows Defender is installed and active." -ForegroundColor Green
        Write-Host "  - Real-time Protection: $($defenderStatus.RealTimeProtectionEnabled)"
        Write-Host "  - Behavior Monitor: $($defenderStatus.BehaviorMonitorEnabled)"
    }
    catch {
        Write-Error "Failed to verify Windows Defender status: $_"
        exit 1
    }
}

<#
.SYNOPSIS
    Creates a backup of current ASR configuration.

.DESCRIPTION
    Exports the current ASR rule settings to a JSON file for recovery purposes.
    Includes timestamp and system information for reference.

.PARAMETER BackupPath
    Full path where the backup file will be saved.

.OUTPUTS
    Backup file in JSON format.
#>
function Backup-ASRConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath
    )

    try {
        Write-Host "`nBacking up current ASR configuration..."

        # Create backup directory if it doesn't exist
        $backupDir = Split-Path -Path $BackupPath -Parent
        if (-not (Test-Path -Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
        }

        # Get current ASR rules
        $asrRules = Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids, AttackSurfaceReductionRules_Actions

        # Create backup object
        $backupObject = @{
            Timestamp = Get-Date -Format "o"
            ComputerName = $env:COMPUTERNAME
            Username = $env:USERNAME
            WindowsBuild = ([int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuildNumber).CurrentBuildNumber)
            ASRConfiguration = $asrRules
        }

        # Convert to JSON and save
        $backupObject | ConvertTo-Json -Depth 10 | Out-File -FilePath $BackupPath -Encoding UTF8 -Force

        Write-Host "✓ Backup created successfully at: $BackupPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to backup ASR configuration: $_"
        throw
    }
}

<#
.SYNOPSIS
    Creates the logging directory for ASR event monitoring.

.DESCRIPTION
    Establishes a directory structure for storing ASR-related logs and audit data.

.PARAMETER LogPath
    Directory path where logs will be stored.

.OUTPUTS
    Directory created if it doesn't exist.
#>
function Initialize-LogDirectory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    try {
        if (-not (Test-Path -Path $LogPath)) {
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
            Write-Host "✓ Log directory created: $LogPath" -ForegroundColor Green
        }
        else {
            Write-Host "✓ Log directory already exists: $LogPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "Failed to create log directory: $_"
        throw
    }
}

<#
.SYNOPSIS
    Configures ASR rules based on the specified mode.

.DESCRIPTION
    Sets Attack Surface Reduction rules to the specified enforcement mode:
    - Block: Enforces all rules, blocking malicious behaviors
    - Audit: Logs violations without blocking
    - Disable: Disables all ASR rules

.PARAMETER Mode
    ASR enforcement mode: 'Block', 'Audit', or 'Disable'

.OUTPUTS
    Configured ASR rules via Set-MpPreference
#>
function Set-ASRRules {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Block", "Audit", "Disable")]
        [string]$Mode
    )

    try {
        Write-Host "`nConfiguring ASR rules to $Mode mode..."

        # Define ASR rule GUIDs and descriptions
        $asrRules = @{
            "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
            "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
            "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
            "75668c1d-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
            "7674ba52-37eb-4a4f-a9a1-f0f9a1619b5c" = "Block Ribbon.InvokeControlEvent"
            "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macro"
            "9e6c8146-7755-472f-ac14-76d7842602f5" = "Block persistence through WMI event subscription"
            "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
            "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
            "d3e037e1-3eb88f86-2fae-1" = "Block JavaScript or VBScript from launching downloaded executable content"
            "d4f940ab-5edb-4efc-b5a9-56f75aff2cf7" = "Block all Office applications from creating child processes"
            "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block credential stealing from the Windows local security authority subsystem"
        }

        # Convert mode to action value
        $actionValue = switch ($Mode) {
            "Block" { 1 }
            "Audit" { 2 }
            "Disable" { 0 }
        }

        # Create arrays for rule IDs and actions
        $ruleIds = @($asrRules.Keys)
        $ruleActions = @($ruleIds | ForEach-Object { $actionValue })

        if ($PSCmdlet.ShouldProcess("Windows Defender ASR Rules", "Set to $Mode mode")) {
            Set-MpPreference -AttackSurfaceReductionRules_Ids $ruleIds -AttackSurfaceReductionRules_Actions $ruleActions -ErrorAction Stop

            Write-Host "✓ ASR rules configured to $Mode mode" -ForegroundColor Green
            Write-Host "  Rules configured: $($ruleIds.Count)"

            foreach ($ruleId in $ruleIds) {
                Write-Host "  - $($asrRules[$ruleId])" -ForegroundColor Cyan
            }
        }
    }
    catch {
        Write-Error "Failed to configure ASR rules: $_"
        throw
    }
}

<#
.SYNOPSIS
    Adds specified paths to ASR exclusions.

.DESCRIPTION
    Excludes files and folders from ASR monitoring to prevent legitimate applications
    from being blocked. Useful for custom software that may trigger false positives.

.PARAMETER ExclusionPath
    File or folder path to exclude from ASR monitoring.

.OUTPUTS
    Updated ASR exclusions via Set-MpPreference
#>
function Add-ASRExclusions {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $false)]
        [string]$ExclusionPath
    )

    if ([string]::IsNullOrEmpty($ExclusionPath)) {
        Write-Host "`n⊘ No exclusion paths specified. Skipping ASR exclusion configuration."
        return
    }

    try {
        Write-Host "`nConfiguring ASR exclusions..."

        if (-not (Test-Path -Path $ExclusionPath)) {
            Write-Warning "Exclusion path does not exist: $ExclusionPath"
            return
        }

        if ($PSCmdlet.ShouldProcess("ASR Exclusions", "Add $ExclusionPath")) {
            # Get current exclusions
            $currentExclusions = (Get-MpPreference).AttackSurfaceReductionOnlyExclusions

            # Add new exclusion if not already present
            if ($currentExclusions -notcontains $ExclusionPath) {
                $exclusionList = @($currentExclusions) + @($ExclusionPath)
                Set-MpPreference -AttackSurfaceReductionOnlyExclusions $exclusionList -ErrorAction Stop

                Write-Host "✓ ASR exclusion added: $ExclusionPath" -ForegroundColor Green
            }
            else {
                Write-Host "⊘ Exclusion already exists: $ExclusionPath" -ForegroundColor Yellow
            }
        }
    }
    catch {
        Write-Error "Failed to add ASR exclusion: $_"
        throw
    }
}

<#
.SYNOPSIS
    Configures Windows Event Log for ASR monitoring.

.DESCRIPTION
    Enables and configures the Microsoft-Windows-Windows Defender/Operational event log
    to capture ASR rule violations and block events. This enables security monitoring.

.OUTPUTS
    Event log configuration changes.
#>
function Enable-ASRLogging {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param()

    try {
        Write-Host "`nConfiguring ASR event logging..."

        $logName = "Microsoft-Windows-Windows Defender/Operational"

        # Check if log exists
        $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue

        if ($null -eq $log) {
            Write-Warning "Event log not found: $logName"
            return
        }

        if ($PSCmdlet.ShouldProcess("Event Log", "Enable $logName")) {
            # Enable the log
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$logName" -Name Enabled -Value 1 -Force -ErrorAction SilentlyContinue

            Write-Host "✓ ASR event logging enabled" -ForegroundColor Green
            Write-Host "  Log location: Event Viewer > Windows Logs > Application > Microsoft-Windows-Windows Defender/Operational" -ForegroundColor Cyan
        }
    }
    catch {
        Write-Error "Failed to enable ASR logging: $_"
    }
}

<#
.SYNOPSIS
    Verifies and displays current ASR configuration.

.DESCRIPTION
    Retrieves and displays the current ASR rule settings, exclusions, and status.
    Used to verify that configuration was applied successfully.

.OUTPUTS
    Console output with current ASR configuration details.
#>
function Get-ASRStatus {
    [CmdletBinding()]
    param()

    try {
        Write-Host "`n========== Current ASR Configuration ==========" -ForegroundColor Cyan

        $mpPreference = Get-MpPreference

        Write-Host "`nASR Rules Status:"
        $ruleIds = $mpPreference.AttackSurfaceReductionRules_Ids
        $ruleActions = $mpPreference.AttackSurfaceReductionRules_Actions

        if ($ruleIds.Count -gt 0) {
            for ($i = 0; $i -lt $ruleIds.Count; $i++) {
                $action = switch ($ruleActions[$i]) {
                    0 { "Disabled" }
                    1 { "Block" }
                    2 { "Audit" }
                    default { "Unknown" }
                }
                Write-Host "  Rule $($i+1): ID=$($ruleIds[$i]) Action=$action" -ForegroundColor Cyan
            }
        }
        else {
            Write-Host "  No ASR rules configured" -ForegroundColor Yellow
        }

        Write-Host "`nASR Exclusions:"
        $exclusions = $mpPreference.AttackSurfaceReductionOnlyExclusions
        if ($exclusions.Count -gt 0) {
            $exclusions | ForEach-Object { Write-Host "  - $_" -ForegroundColor Cyan }
        }
        else {
            Write-Host "  No exclusions configured" -ForegroundColor Yellow
        }

        Write-Host "`n===============================================" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Failed to retrieve ASR status: $_"
    }
}

<#
.SYNOPSIS
    Displays execution summary and next steps.

.DESCRIPTION
    Provides a summary of all actions taken and recommendations for next steps,
    including monitoring and testing.

.PARAMETER Mode
    The ASR mode that was configured.

.PARAMETER LogPath
    Path to logs for user reference.
#>
function Show-ExecutionSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Mode,

        [Parameter(Mandatory = $true)]
        [string]$LogPath
    )

    Write-Host "`n" -ForegroundColor Green
    Write-Host "╔════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║     ASR Implementation Completed Successfully      ║" -ForegroundColor Green
    Write-Host "╚════════════════════════════════════════════════════╝" -ForegroundColor Green

    Write-Host "`nConfiguration Summary:"
    Write-Host "  • Mode: $Mode" -ForegroundColor Green
    Write-Host "  • Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
    Write-Host "  • Log Path: $LogPath" -ForegroundColor Green

    Write-Host "`nRecommended Next Steps:"
    Write-Host "  1. Monitor Event Log for ASR events (Operational log)"
    Write-Host "  2. Test applications that interact with Office or sensitive processes"
    Write-Host "  3. Review audit logs if running in 'Audit' mode"
    Write-Host "  4. Adjust exclusions as needed for business applications"
    Write-Host "  5. Gradually transition from 'Audit' to 'Block' mode after validation"

    if ($Mode -eq "Audit") {
        Write-Host "`n⚠ Important: You are running in AUDIT mode." -ForegroundColor Yellow
        Write-Host "  This means ASR violations are logged but not blocked." -ForegroundColor Yellow
        Write-Host "  Review logs for 2-4 weeks before transitioning to BLOCK mode." -ForegroundColor Yellow
    }
}

#endregion Functions

#region Main Script Execution

try {
    Write-Host "╔════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║   Windows 10 Attack Surface Reduction Installer   ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════╝" -ForegroundColor Cyan

    # Pre-flight checks
    Write-Host "`nPerforming pre-flight checks..." -ForegroundColor Yellow
    Test-AdminPrivileges
    Test-WindowsVersion
    Test-DefenderStatus

    # Backup current configuration
    if (-not $SkipBackup) {
        Backup-ASRConfiguration -BackupPath $BackupPath
    }

    # Initialize logging
    Initialize-LogDirectory -LogPath $LogPath

    # Configure ASR rules
    Set-ASRRules -Mode $Mode

    # Add exclusions if specified
    Add-ASRExclusions -ExclusionPath $ExclusionPath

    # Enable logging
    Enable-ASRLogging

    # Display current status
    Get-ASRStatus

    # Show summary
    Show-ExecutionSummary -Mode $Mode -LogPath $LogPath
}
catch {
    Write-Error "Script execution failed: $_"
    Write-Host "`nRolling back changes..." -ForegroundColor Yellow
    
    if (-not $SkipBackup -and (Test-Path -Path $BackupPath)) {
        Write-Host "To restore previous settings, use the backup file at: $BackupPath" -ForegroundColor Yellow
    }
    
    exit 1
}

#endregion Main Script Execution
