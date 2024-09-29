# Define the URL for the DirectX installer
$directxUrl = "https://download.microsoft.com/download/1/1C/1C1E1C1E-1C1E-1C1E-1C1E-1C1E1C1E1C1E/directx_Jun2010_redist.exe"

# Create a temporary directory
$tempDir = New-Item -ItemType Directory -Path "$env:TEMP\DirectXTemp" -Force

# Define the path for the downloaded installer
$installerPath = "$tempDir\directx_Jun2010_redist.exe"

# Download the DirectX installer
Invoke-WebRequest -Uri $directxUrl -OutFile $installerPath

# Extract the installer files to the temporary directory
Start-Process -FilePath $installerPath -ArgumentList "/Q /T:$tempDir" -Wait

# Run the DirectX setup silently
Start-Process -FilePath "$tempDir\DXSETUP.exe" -ArgumentList "/silent" -Wait

# Clean up the temporary directory
Remove-Item -Path $tempDir -Recurse -Force
