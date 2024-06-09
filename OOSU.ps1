$OOSU_filepath = "$ENV:temp\OOSU10.exe"

    $Initial_ProgressPreference = $ProgressPreference
    $ProgressPreference = "SilentlyContinue" # Disables the Progress Bar to drasticly speed up Invoke-WebRequest
    Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
    $oosu_config = "$ENV:temp\ooshutup10.cfg"
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ChrisTitusTech/winutil/main/config/ooshutup10.cfg" -OutFile $oosu_config
    Write-Host "Applying recommended OO Shutup 10 Policies"
    Start-Process $OOSU_filepath -ArgumentList "$oosu_config /quiet" -Wait
