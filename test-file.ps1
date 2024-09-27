# Define URLs
$zipUrl = "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/2.4.0.4/nvidiaProfileInspector.zip"
$configUrl = "https://raw.githubusercontent.com/h3kt0rx/fresh-install-win11/refs/heads/main/Base%20Profile.nip"

# Define temporary paths
$tempDir = "$env:TEMP\nvidiaProfileInspector"
$zipPath = "$tempDir\nvidiaProfileInspector.zip"
$extractPath = "$tempDir\nvidiaProfileInspector"

# Create temporary directory
New-Item -ItemType Directory -Force -Path $tempDir

# Download the ZIP file
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath

# Extract the ZIP file
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force

# Download the configuration file
Invoke-WebRequest -Uri $configUrl -OutFile "$extractPath\Base Profile.nip"

# Change directory to where the executable is located
Set-Location -Path $extractPath

# Run the command to import the profile silently
$process = Start-Process -FilePath ".\nvidiaProfileInspector.exe" -ArgumentList "-silentImport `".\Base Profile.nip`"" -PassThru

# Wait for the process to exit
$process.WaitForExit()

# Change directory back to a safe location
Set-Location -Path $env:TEMP

# Clean up
Remove-Item -Recurse -Force -Path $tempDir