# Intune Remediation Script - Remediation
# Purpose: Force install all pending Windows Updates and restart if required
# This script will download and install all available updates without user interaction

param()

try {
    Write-Output "Starting Windows Update remediation..."
    Write-Output "Timestamp: $(Get-Date)"
    
    # Create Windows Update session
    $updateSession = New-Object -ComObject Microsoft.Update.Session
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    
    # Search for all pending updates
    Write-Output "Searching for pending Windows Updates..."
    $searchResult = $updateSearcher.Search("IsInstalled=0")
    $pendingUpdates = $searchResult.Updates
    
    Write-Output "Found $($pendingUpdates.Count) pending update(s)"
    
    if ($pendingUpdates.Count -eq 0) {
        Write-Output "No updates available. Device is already up to date."
        exit 0
    }
    
    # Display pending updates
    Write-Output "Pending updates:"
    foreach ($update in $pendingUpdates) {
        Write-Output "- $($update.Title)"
    }
    
    # Create update collection
    $updateCollection = New-Object -ComObject Microsoft.Update.UpdateColl
    foreach ($update in $pendingUpdates) {
        $updateCollection.Add($update) | Out-Null
    }
    
    # Create downloader
    Write-Output "Downloading updates..."
    $downloader = $updateSession.CreateUpdateDownloader()
    $downloader.Updates = $updateCollection
    $downloader.Download() | Out-Null
    Write-Output "Download completed"
    
    # Install updates
    Write-Output "Installing updates..."
    $installer = $updateSession.CreateUpdateInstaller()
    $installer.Updates = $updateCollection
    $installationResult = $installer.Install()
    
    Write-Output "Installation result code: $($installationResult.ResultCode)"
    Write-Output "Reboot required: $($installationResult.RebootRequired)"
    
    # Check if reboot is required
    if ($installationResult.RebootRequired) {
        Write-Output "Updates installed successfully. Reboot is required."
        Write-Output "Scheduling immediate restart..."
        
        # Force restart immediately
        shutdown /r /t 600 /c "Windows Updates installed by Intune. Device will restart in 10 Minutes. Please save your work." /f
        
        Write-Output "Restart initiated"
        exit 0
    }
    else {
        Write-Output "Updates installed successfully. No reboot required."
        exit 0
    }
}
catch {
    Write-Output "Error during Windows Update remediation: $_"
    Write-Output "Exception: $($_.Exception)"
    exit 1
}
