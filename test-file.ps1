# Define the URL for the DirectX installer
$directxUrl = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"

# Define the path for the downloaded installer
$installerPath = "$env:TEMP\directx_installer.exe"

# Download the DirectX installer
Invoke-WebRequest -Uri $directxUrl -OutFile $installerPath

# Run the installer silently
Start-Process -FilePath $installerPath -ArgumentList "/silent" -Wait

# Optionally, remove the installer after execution
Remove-Item -Path $installerPath -Force