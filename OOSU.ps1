# Replace with your Gist's raw URL
$gistUrl = "https://github.com/h3kt0rx/fresh-install-win11/edit/main/OOSU.ps1"

#Option 1
#Invoke-RestMethod -Uri $gistUrl | Invoke-Expression

#Option 2
Invoke-Expression ((New-Object System.net.WebClient).DownloadString('$gistUrl'))

$OOSU_filepath = "$ENV:temp\OOSU10.exe"
$Initial_ProgressPreference = $ProgressPreference
$ProgressPreference = "SilentlyContinue" # Disables the Progress Bar to drasticly speed up Invoke-WebRequest
$oosu_config = "$ENV:temp\ooshutup10.cfg"
Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
Invoke-WebRequest -Uri "https://github.com/h3kt0rx/fresh-install-win11/blob/main/cfg/ooshutup10.cfg" -OutFile $oosu_config
Write-Host "Applying recommended OO Shutup 10 Policies"
Start-Process $OOSU_filepath -ArgumentList "$oosu_config /quiet" -Wait
