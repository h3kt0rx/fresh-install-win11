# Define the URL for the DirectX installer
$directxUrl = "https://download.microsoft.com/download/1/8/3/183E4F90-9F52-4E85-B733-FD13F9B0CE5F/directx_websetup.exe"

# Define the path for the downloaded installer
$installerPath = "$env:TEMP\directx_websetup.exe"

# Download the DirectX installer
Invoke-WebRequest -Uri $directxUrl -OutFile $installerPath

# Run the installer silently
Start-Process -FilePath $installerPath -ArgumentList "/install", "/silent" -Wait

# Optionally, remove the installer after execution
Remove-Item -Path $installerPath -Force
