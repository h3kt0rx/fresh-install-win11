# Define the URL and paths
$DXFileUri = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"
$DXFileUri2 = "https://www.7-zip.org/a/7z2301-x64.exe"
$DXDestination = "$env:TEMP\directx_Jun2010_redist.exe"
$DXDestination2 = "$env:TEMP\7-Zip.exe"
$DXExtractPath = "$env:TEMP\DirectX_Install"

# Download the DirectX Web Setup
$DXbitsJobObj = Start-BitsTransfer -Source $DXFileUri -Destination $DXDestination
$DXbitsJobObj = Start-BitsTransfer -Source $DXFileUri2 -Destination $DXDestination2

switch ($DXbitsJobObj.JobState) {
    'Transferred' {
        Complete-BitsTransfer -BitsJob $DXbitsJobObj
        break
    }
    'Error' {
        throw 'Error downloading'
    }
}

# Create the extraction directory if it doesn't exist
if (-Not (Test-Path -Path $DXExtractPath)) {
    New-Item -ItemType Directory -Path $DXExtractPath | Out-Null
}

Start-Process -wait "$env:TEMP\7-Zip.exe" /S
# extract files with 7zip
cmd /c "C:\Program Files\7-Zip\7z.exe" x "$DXDestination" -o"$DXExtractPath" -y | Out-Null
# install direct x
Start-Process "$DXExtractPath\DXSETUP.exe" -ArgumentList "/silent" -Wait

# Clean up the installer
Remove-Item -Path $DXDestination -Force
Write-Output "Updated DirectX"