# Define the URL for the DirectX installer
$directxUrl = "https://download.microsoft.com/download/9/4/5/945A8F9E-18F8-4E1D-9C6B-49C8C4D8E4B6/directx_Jun2010_redist.exe"

# Define the path for the downloaded installer
$installerPath = "$env:TEMP\directx_installer.exe"

# Download the DirectX installer
Invoke-WebRequest -Uri $directxUrl -OutFile $installerPath

# Run the installer silently
Start-Process -FilePath $installerPath -ArgumentList "/silent" -Wait

# Optionally, remove the installer after execution
Remove-Item -Path $installerPath -Force