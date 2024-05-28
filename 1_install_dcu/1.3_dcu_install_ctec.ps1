# DCUSetup_2024-05-28_Clint_Thomson.ps1
# Description: This script uninstalls existing Dell Command Update installations and then installs Dell Command Update using the latest installer from the specified URL. It includes error handling, logging, retry logic, and checksum verification.

# User editable variables
$installerUrl = "insert download link here"
$installerPath = "insert installer path here"
$logFilePath = "insert logfile path here"
$retryCount = 3
$retryDelay = 5  # in seconds
$uninstallLogPath = "insert logfile path here"
$knownChecksum = "insert checksum"

# Function to log messages
function Log-Message {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Write-Host $logEntry
    Add-Content -Path $logFilePath -Value $logEntry
}

# Function to check administrative privileges
function Check-Admin {
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Log-Message "Script is not running with administrative privileges. Exiting."
        exit 1
    }
}

# Function to check if the machine is a Dell
function Check-Manufacturer {
    $manufacturer = (Get-WmiObject -Class Win32_ComputerSystem).Manufacturer
    if ($manufacturer -notmatch "Dell") {
        Log-Message "This script is only for Dell machines. Exiting."
        exit 1
    } else {
        Log-Message "Manufacturer check passed: Dell machine detected."
    }
}

# Function to ensure a directory exists
function Ensure-DirectoryExists {
    param (
        [string]$directoryPath
    )
    if (-not (Test-Path -Path $directoryPath)) {
        New-Item -Path $directoryPath -ItemType Directory | Out-Null
        Log-Message "Created directory: $directoryPath"
    } else {
        Log-Message "Directory already exists: $directoryPath"
    }
}

# Function to compute SHA256 checksum
function Get-FileChecksum {
    param (
        [string]$filePath
    )
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = [System.IO.File]::OpenRead($filePath)
    $hashBytes = $sha256.ComputeHash($stream)
    $stream.Close()
    return [BitConverter]::ToString($hashBytes) -replace '-', ''
}

# Function to uninstall Dell Command Update using the uninstaller
function Uninstall-DellCommandUpdate {
    $Name = "Dell Command | Update"
    $Timestamp = Get-Date -Format "yyyy-MM-dd_THHmmss"
    $UninstallLogFile = "$uninstallLogPath\Dell-CU-Uninst_$Timestamp.log"
    $ProgramList = @(
        "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    try {
        $Programs = Get-ItemProperty $ProgramList -ErrorAction SilentlyContinue
        $App = ($Programs | Where-Object { $_.DisplayName -eq $Name -and $_.UninstallString -like "*msiexec*" }).PSChildName
        
        if ($App) {
            Log-Message "Stopping any running Dell Command Update processes..."
            Get-Process | Where-Object { $_.ProcessName -eq "DellCommandUpdate" } | Stop-Process -Force

            Log-Message "Uninstalling Dell Command Update using msiexec..."
            $Params = @(
                "/qn",
                "/norestart",
                "/X",
                "$App",
                "/L*V `"$UninstallLogFile`""
            )

            Start-Process -FilePath "msiexec.exe" -ArgumentList $Params -Wait -NoNewWindow
            Log-Message "Dell Command Update uninstalled successfully using msiexec."
        } else {
            Log-Message "No existing Dell Command Update installation found to uninstall."
        }
    } catch {
        Log-Message "Failed to uninstall Dell Command Update using msiexec: $_"
    }

    # Delete the installation directories - Cleanup before install
    $installPaths = @(
        "C:\Program Files\Dell\CommandUpdate",
        "C:\Program Files (x86)\Dell\CommandUpdate"
    )
    foreach ($path in $installPaths) {
        if (Test-Path -Path $path) {
            Log-Message "Dell Command Update found at $path. Deleting directory..."
            try {
                Remove-Item -Path $path -Recurse -Force
                Log-Message "Deleted Dell Command Update directory at $path."
            } catch {
                $errorMessage = $_.Exception.Message
                Log-Message ("Failed to delete Dell Command Update directory at " + $path + ": " + $errorMessage)
            }
        }
    }
}

# Function to download and install Dell Command Update using the installer from the specified URL
function Install-DellCommandUpdateUsingInstaller {
    $success = $false
    for ($i = 0; $i -lt $retryCount; $i++) {
        try {
            # Get the expected file size from the server
            Log-Message "Checking the file size of the installer on the server..."
            $response = Invoke-WebRequest -Uri $installerUrl -Method Head
            $expectedSize = $response.Headers["Content-Length"]

            if ($null -eq $expectedSize) {
                Log-Message "Failed to retrieve the file size from the server."
                continue
            }
            
            Log-Message "Expected file size: $expectedSize bytes."

            Log-Message "Downloading Dell Command Update installer..."
            Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath

            # Verify the size of the downloaded file
            $actualSize = (Get-Item $installerPath).Length
            Log-Message "Actual downloaded file size: $actualSize bytes."

            if ($expectedSize -ne $actualSize) {
                Log-Message "Downloaded file size does not match the expected size. Retrying..."
                Remove-Item $installerPath -Force
                Start-Sleep -Seconds $retryDelay
                continue
            }

            # Verify the SHA256 checksum of the downloaded file
            $downloadedChecksum = Get-FileChecksum -filePath $installerPath
            if ($downloadedChecksum -eq $knownChecksum) {
                Log-Message "Checksum verification passed. Checksum: $downloadedChecksum"
                Log-Message "Installing Dell Command Update using downloaded installer..."
                Start-Process -FilePath $installerPath -ArgumentList '/s' -Wait -NoNewWindow
                Log-Message "Dell Command Update installed successfully using the downloaded installer."
                Remove-Item $installerPath -Force
                $success = $true
                break
            } else {
                Log-Message "Checksum verification failed. Downloaded checksum: $downloadedChecksum, Known checksum: $knownChecksum. Retrying..."
                Remove-Item $installerPath -Force
                Start-Sleep -Seconds $retryDelay
            }

        } catch {
            Log-Message "Failed to install Dell Command Update using the downloaded installer: $_"
            Start-Sleep -Seconds $retryDelay
        }
    }

    if (-not $success) {
        Log-Message "Checksum verification failed after $retryCount attempts. Downloaded checksum: $downloadedChecksum, Known checksum: $knownChecksum. Exiting."
        exit 1
    }

    return $success
}

# Main script logic
try {
    Check-Admin

    # Ensure necessary directories exist
    Ensure-DirectoryExists "C:\Celeratec\Logs"
    Ensure-DirectoryExists "C:\Celeratec\Installers"

    Check-Manufacturer

    Uninstall-DellCommandUpdate

    $installSuccess = Install-DellCommandUpdateUsingInstaller

    if ($installSuccess) {
        Ninja-Property-Set dcuInstallStatus "Success"
        Log-Message 'Dell Command Update successfully installed'
    } else {
        Ninja-Property-Set dcuInstallStatus "Failure"
        Log-Message 'Dell Command Update installation failed after retries'
    }
} catch {
    Log-Message "Error during installation/uninstallation process: $_"
    Ninja-Property-Set dcuInstallStatus "Failure"
}
