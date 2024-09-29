# Define the URL for the DirectX installer
$directXUrl = "https://download.microsoft.com/download/3/2/B/32B20E71-0676-4B39-B07D-447A5E8E6A49/dxwebsetup.exe"

# Define the temporary directory
$tempDir = [System.IO.Path]::GetTempPath()
$installerPath = Join-Path -Path $tempDir -ChildPath "dxwebsetup.exe"

# Download the DirectX installer
Invoke-WebRequest -Uri $directXUrl -OutFile $installerPath

# Start the installer silently in the background
Start-Process -FilePath $installerPath -ArgumentList "/silent" -NoNewWindow -Wait

# Optionally, you can delete the installer after installation
Remove-Item -Path $installerPath -Force
