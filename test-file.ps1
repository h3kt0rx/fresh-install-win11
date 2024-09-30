$FileUri = "https://download.microsoft.com/download/8/4/A/84A35BF1-DAFE-4AE8-82AF-AD2AE20B6B14/directx_Jun2010_redist.exe"
$Destination = "$env:TEMP/directx_Jun2010_redist.exe"
$destinationPath = "$env:TEMP/directx_Jun2010_redist"
$runFile = "$env:TEMP/$destinationPath/DXSETUP.exe"
$bitsJobObj = Start-BitsTransfer $FileUri -Destination $Destination

switch ($bitsJobObj.JobState) {

    'Transferred' {
        Complete-BitsTransfer -BitsJob $bitsJobObj
        break
    }

    'Error' {
        throw 'Error downloading'
    }
}

Expand-Archive -Path $Destination -DestinationPath $destinationPath
Start-Process -Wait $runFile -ArgumentList "/silent"