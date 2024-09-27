# Define the URL for the DirectX ZIP installer
$zipUrl = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"

# Define the paths
$zipPath = "$env:TEMP\directx_installer.zip"
$extractPath = "$env:TEMP\directx_installer"

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
        exit
    }
}

# Download the DirectX ZIP installer
Get-FileFromWeb -url $zipUrl -outputPath $zipPath

# Check if the ZIP file exists
if (Test-Path $zipPath) {
    # Create extraction directory
    New-Item -ItemType Directory -Path $extractPath -Force
    
    # Unzip the file
    Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force
    
    # Check if the extracted installer exists
    $installerPath = Join-Path -Path $extractPath -ChildPath "directx_websetup.exe"
    
    if (Test-Path $installerPath) {
        # Run the installer silently
        Start-Process -FilePath $installerPath -ArgumentList "/install", "/silent" -Wait
        # Optionally, remove the installer and ZIP after execution
        Remove-Item -Path $installerPath -Force
        Remove-Item -Path $zipPath -Force
        Remove-Item -Path $extractPath -Recurse -Force
    } else {
        Write-Host "The installer was not found in the extracted files."
    }
} else {
    Write-Host "The ZIP file was not downloaded successfully."
}
