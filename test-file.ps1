# Define the URL and paths
$FileUri = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/dxwebsetup.exe"
$Destination = "$env:TEMP\dxwebsetup.exe"
$ExtractPath = "$env:TEMP\DirectX_Install"

# Download the DirectX Web Setup
$bitsJobObj = Start-BitsTransfer -Source $FileUri -Destination $Destination

switch ($bitsJobObj.JobState) {
    'Transferred' {
        Complete-BitsTransfer -BitsJob $bitsJobObj
        break
    }
    'Error' {
        throw 'Error downloading'
    }
}

# Create the extraction directory if it doesn't exist
if (-Not (Test-Path -Path $ExtractPath)) {
    New-Item -ItemType Directory -Path $ExtractPath | Out-Null
}

# Run the installer to extract files to the specified directory
Start-Process -FilePath $Destination -ArgumentList "/C /T:$ExtractPath" -Wait

# Optional: Check the extracted files
Get-ChildItem -Path $ExtractPath

# Clean up the installer
Remove-Item -Path $Destination -Force
