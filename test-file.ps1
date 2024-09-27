# Define the URL for the DirectX installer
$directxUrl = "https://download.microsoft.com/download/1/8/3/183E4F90-9F52-4E85-B733-FD13F9B0CE5F/directx_websetup.exe"

# Define the path for the downloaded installer
$installerPath = "$env:TEMP\directx_installer.exe"

# Download the DirectX installer
try {
    Invoke-WebRequest -Uri $directxUrl -OutFile $installerPath -ErrorAction Stop
} catch {
    Write-Host "Failed to download the DirectX installer: $_"
    exit
}

# Check if the file exists
if (Test-Path $installerPath) {
    # Run the installer silently
    Start-Process -FilePath $installerPath -ArgumentList "/install", "/silent" -Wait
    # Optionally, remove the installer after execution
    Remove-Item -Path $installerPath -Force
} else {
    Write-Host "The installer was not downloaded successfully."
}
