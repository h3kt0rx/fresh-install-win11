# Define the URL for the DirectX installer
$directxUrl = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"

# Define the path for the downloaded installer
$installerPath = "$env:TEMP\directx_installer.exe"

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
        Start-Sleep
    }
}

# Download the DirectX installer
Get-FileFromWeb -url $directxUrl -outputPath $installerPath

# Check if the file exists
if (Test-Path $installerPath) {
    # Run the installer silently
    Start-Process -FilePath $installerPath -ArgumentList "/install", "/silent" -Wait
    # Optionally, remove the installer after execution
    Remove-Item -Path $installerPath -Force
    Start-Sleep
} else {
    Write-Host "The installer was not downloaded successfully."
    Start-Sleep
}
