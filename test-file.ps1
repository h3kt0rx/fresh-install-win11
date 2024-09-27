# Define the URL for the DirectX installer
$directxUrl = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"

# Define the path for the downloaded installer
$installerPath = "$env:TEMP\dxwebsetup.exe"

# Function to download the file
function Get-FileFromWeb {
    param (
        [string]$url,
        [string]$outputPath
    )

    $webClient = New-Object System.Net.WebClient
    try {
        $webClient.DownloadFile($url, $outputPath)
    } catch {
        Write-Host "Failed to download the file: $_"
        return $false
    }
    return $true
}

# Download the DirectX installer
if (Get-FileFromWeb -url $directxUrl -outputPath $installerPath) {
    # Check if the file exists
    if (Test-Path $installerPath) {
        # Run the installer silently
        try {
            Start-Process -FilePath $installerPath -ArgumentList "/silent" -Wait -ErrorAction Stop
        } catch {
            Write-Host "Failed to run the installer: $_"
        }
        
        # Optionally, remove the installer after execution
        Remove-Item -Path $installerPath -Force
    } else {
        Write-Host "The installer was not downloaded successfully."
    }
} else {
    Write-Host "Download process failed."
}
