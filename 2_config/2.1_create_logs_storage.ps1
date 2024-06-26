param (
    # [Parameter(Mandatory=$true)]
    [string]$env:folderPath
)

try {
    # Construct the full folder path on the C drive
    $location = "C:\$env:folderPath"

    # Check if the specified folder exists
    if (Test-Path -Path $location -PathType Container) {
        Write-Host "Folder '$location' exists."

        # Define the subfolder name
        $subfolderName = "logs"
        $subfolderPath = Join-Path -Path $location -ChildPath $subfolderName

        # Check if the subfolder already exists
        if (-not (Test-Path -Path $subfolderPath -PathType Container)) {
            # Create the subfolder if it doesn't exist
            New-Item -Path $subfolderPath -ItemType Directory
            Write-Host "Subfolder '$subfolderName' created inside '$location'."
        } else {
            Write-Host "Subfolder '$subfolderName' already exists inside '$location'."
        }

        # Set NinjaRMM property
        # Note: Ensure Ninja-Property-Set command is correctly configured
        Ninja-Property-Set dcuLogLocation $subfolderPath
    } else {
        Write-Host "Folder '$location' does not exist."
    }
} catch {
    Write-Host "An error occurred: $_"
}
