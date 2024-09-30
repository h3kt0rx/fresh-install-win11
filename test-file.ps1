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
Get-FileFromWeb -URL "https://www.7-zip.org/a/7z2301-x64.exe" -File "$env:TEMP\7-Zip.exe"
# Run the installer to extract files to the specified directory
Start-Process -FilePath $Destination -ArgumentList "$ExtractPath" -Wait
Start-Process -wait "$env:TEMP\7-Zip.exe" /S
# extract files with 7zip
cmd /c "C:\Program Files\7-Zip\7z.exe" x "$Destination" -o"$ExtractPath" -y | Out-Null
# install direct x
Start-Process "$ExtractPath\DXSETUP.exe" -ArgumentList "/silent"

# Clean up the installer
Remove-Item -Path $Destination -Force
