# Define the URL and paths
$FileUri = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/dxwebsetup.exe"
$FileUri2 = "https://www.7-zip.org/a/7z2301-x64.exe"
$Destination = "$env:TEMP\dxwebsetup.exe"
$Destination2 = "$env:TEMP\7-Zip.exe"
$ExtractPath = "$env:TEMP\DirectX_Install"

# Download the DirectX Web Setup
$bitsJobObj = Start-BitsTransfer -Source $FileUri -Destination $Destination
$bitsJobObj = Start-BitsTransfer -Source $FileUri2 -Destination $Destination2

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

Start-Process -wait "$env:TEMP\7-Zip.exe" /S
# extract files with 7zip
cmd /c "C:\Program Files\7-Zip\7z.exe" x "$Destination" -o"$ExtractPath" -y | Out-Null
# install direct x
Start-Process "$ExtractPath\DXSETUP.exe" -ArgumentList "/silent"

# Clean up the installer
Remove-Item -Path $Destination -Force
