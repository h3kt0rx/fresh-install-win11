# Define the file URI and paths
$FileUri = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"
$Destination = "$env:TEMP\directx_Jun2010_redist.exe"
$destinationPath = "$env:TEMP\directx_Jun2010_redist"
$runFile = "$destinationPath\DXSETUP.exe"

# Download the file using BITS
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

# Create the destination directory if it doesn't exist
if (-Not (Test-Path -Path $destinationPath)) {
    New-Item -ItemType Directory -Path $destinationPath | Out-Null
}

# Extract the contents (the DirectX installer is not a standard archive)
# In this case, you need to run the installer directly instead of extracting.
Start-Process -FilePath $Destination -ArgumentList "/silent" -Wait

# Clean up
Remove-Item -Path $Destination
