# Define the URL for the DirectX installer
$directxUrl = "https://download.microsoft.com/download/1/8/3/183E4F90-9F52-4E85-B733-FD13F9B0CE5F/directx_websetup.exe"

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
        exit
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
} else {
    Write-Host "The installer was not downloaded successfully."
}
