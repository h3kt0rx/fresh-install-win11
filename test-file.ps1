# Define the file URI and paths
$FileUri = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"
$Destination = "$env:TEMP\directx_Jun2010_redist.exe"
$runFile = $Destination

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

# Start the installer with silent mode
Start-Process -FilePath $runFile -ArgumentList "/silent" -Wait

# Clean up
Remove-Item -Path $Destination -Force
