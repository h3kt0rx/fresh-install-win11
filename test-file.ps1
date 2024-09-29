# Define the URL for the DirectX installer
$directXUrl = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"

# Define the temporary directory
$tempDir = [System.IO.Path]::GetTempPath()
$installerPath = Join-Path -Path $tempDir -ChildPath "dxwebsetup.exe"

# Download the DirectX installer
Invoke-WebRequest -Uri $directXUrl -OutFile $installerPath

# Start the installer silently in the background
Start-Process -FilePath $installerPath -ArgumentList "/silent" -NoNewWindow -Wait

# Optionally, you can delete the installer after installation
Remove-Item -Path $installerPath -Force
