<# -----------------------------------------------------------------------
Copy and Paste the following in Powershell as Administrator:
--------------------------------------------------------------------------
Set-ExecutionPolicy Unrestricted
iwr -useb https://christitus.com/win | iex
--------------------------------------------------------------------------#>
############################################################################################################################################################
<# Check if the script is running as Administrator #>
############################################################################################################################################################
Write-Host "Set script as Administrator" 
$principal = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Restart the script with Administrator privileges
    Start-Process PowerShell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}
# Set window title for the Administrator session
$Host.UI.RawUI.WindowTitle = "$($myInvocation.MyCommand.Definition) (Administrator)"
# Customize console appearance
$Host.UI.RawUI.BackgroundColor = "Black"
$Host.PrivateData.ProgressBackgroundColor = "Black"
$Host.PrivateData.ProgressForegroundColor = "White"
Write-Host "Done." 
############################################################################################################################################################
<# Disable User Account Control (UAC) #>
############################################################################################################################################################
Write-Host "Disable UAC Notification" 
$UACValue = "0" # 0 = Never Notify
$UACKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
# Set the registry value
Set-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorAdmin" -Value $UACValue
Set-ItemProperty -Path $UACKey -Name "ConsentPromptBehaviorUser" -Value $UACValue
Set-ItemProperty -Path $UACKey -Name "EnableLUA" -Value "0"
Write-Host "Done." 
############################################################################################################################################################
<# NVIDIA Profile #>
############################################################################################################################################################
Write-Host "Setting NVIDIA Profile" 
# Define URLs
$zipUrl = "https://github.com/Orbmu2k/nvidiaProfileInspector/releases/download/2.4.0.4/nvidiaProfileInspector.zip"
$configUrl = "https://raw.githubusercontent.com/h3kt0rx/fresh-install-win11/refs/heads/main/Base%20Profile.nip"
# Define temporary paths
$tempDir = "$env:TEMP\nvidiaProfileInspector"
$zipPath = "$tempDir\nvidiaProfileInspector.zip"
$extractPath = "$tempDir\nvidiaProfileInspector"
# Create the directory and suppress output
New-Item -ItemType Directory -Force -Path $tempDir | Out-Null
# Download the ZIP file and suppress output
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath | Out-Null
# Extract the ZIP file and suppress output
Expand-Archive -Path $zipPath -DestinationPath $extractPath -Force | Out-Null
# Download the configuration file and suppress output
Invoke-WebRequest -Uri $configUrl -OutFile "$extractPath\Base Profile.nip" | Out-Null
# Run the command to import the profile silently
$process = Start-Process -FilePath $extractPath\nvidiaProfileInspector.exe -ArgumentList "-silentImport `"$extractPath\Base Profile.nip`"" -PassThru
# Wait for the process to exit
$process.WaitForExit()
# Clean up
Remove-Item -Recurse -Force -Path $tempDir
Write-Host "Done."
############################################################################################################################################################
<# Script to Disable Core Isolation and Enable Game Mode #>
############################################################################################################################################################
Write-Host "Enabling Game Mode and Disable Core Isolation" 
# Function to Enable Game Mode
function Enable-GameMode {
    $gameModePath = "HKCU:\SOFTWARE\Microsoft\GameBar"
    
    # Check if the path exists, create it if it doesn't
    if (-not (Test-Path $gameModePath)) {
        New-Item -Path $gameModePath -PropertyType DWord -Force
    }
    
    # Set or create properties
    Set-ItemProperty -Path $gameModePath -Name "AutoGameModeEnabled" -Value 1 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path $gameModePath -Name "UseGameMode" -Value 1 -Force -ErrorAction SilentlyContinue
}

# Function to Disable Core Isolation Memory Integrity
function Disable-CoreIsolation {
    $memoryIntegrityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceGuard"
    
    if (-not (Test-Path $memoryIntegrityPath)) {
        New-Item -Path $memoryIntegrityPath -PropertyType DWord -Force
    }

    # Set Memory Integrity to disabled
    Set-ItemProperty -Path $memoryIntegrityPath -Name "EnableVirtualizationBasedSecurity" -Value 0 -ErrorAction SilentlyContinue
}

# Execute Optimization Functions
Disable-CoreIsolation
Enable-GameMode
Write-Host "Done."
############################################################################################################################################################
<# Run O&O ShutUp #>
############################################################################################################################################################
Write-Host "Running O&O ShutUp"
$OOSU_filepath = "$ENV:temp\OOSU10.exe"
$oosu_config = "$ENV:temp\ooshutup10.cfg"
Invoke-WebRequest -Uri "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -OutFile $OOSU_filepath
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/h3kt0rx/fresh-install-win11/bcd88675cbdc59d3af7cc6fc6b5ca8430840e7ce/cfg/ooshutup10.cfg" -OutFile $oosu_config
Write-Host "Applying personal O&O Shutup 10 Policies"
Start-Process $OOSU_filepath -ArgumentList "$oosu_config /quiet" -Wait
Write-Host "Done." 
############################################################################################################################################################
<# Remove Gamebar #>
############################################################################################################################################################
Write-Host "Removing Gamebar" 
# Define registry paths and values
$values = @{
    "HKCU:\System\GameConfigStore" = "GameDVR_Enabled"
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" = "AppCaptureEnabled"
}

foreach ($path in $values.Keys) {
    $name = $values[$path]
    if (-not (Test-Path "$path\$name")) { New-Item -Path $path -Force }
    Set-ItemProperty -Path $path -Name $name -Value 0 -Type DWord | Out-Null
}
# stop gamebar running
Stop-Process -Force -Name GameBar -ErrorAction SilentlyContinue | Out-Null
# uninstall gamebar
Get-AppxPackage -allusers *Microsoft.XboxGameOverlay* | Remove-AppxPackage
Get-AppxPackage -allusers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage
Write-Host "Done." 
############################################################################################################################################################
<# Monitor Optimizations #>
############################################################################################################################################################





############################################################################################################################################################
<# Powerplan #>
############################################################################################################################################################
Write-Host "Setting Powerplan" 
# Duplicate the ultimate power plan
$sourcePlan = "e9a42b02-d5df-448d-aa00-03f14749eb61"
$targetPlan = "99999999-9999-9999-9999-999999999999"
cmd /c "powercfg /duplicatescheme $sourcePlan $targetPlan >nul 2>&1"
# Set the ultimate power plan as active
cmd /c "powercfg /SETACTIVE $targetPlan >nul 2>&1"
# Get the currently active power scheme
$activePlan = powercfg /getactivescheme | Select-String -Pattern "GUID: ([\w-]+)" | ForEach-Object { $_.Matches.Groups[1].Value }
# Retrieve all power plans
$powerPlans = powercfg /list | Select-String -Pattern "GUID: ([\w-]+)" | ForEach-Object { $_.Matches.Groups[1].Value }
# Delete all power plans except the active one
foreach ($plan in $powerPlans) {
    if ($plan -ne $activePlan) {
        powercfg -delete $plan
    }
}
# Disable hibernate
powercfg /hibernate off
# Disable hibernate settings in the registry
$regPath1 = "HKLM:\SYSTEM\CurrentControlSet\Control\Power"
Set-ItemProperty -Path $regPath1 -Name "HibernateEnabled" -Value 0 -Type DWord -Force
Set-ItemProperty -Path $regPath1 -Name "HibernateEnabledDefault" -Value 0 -Type DWord -Force
# Disable lock option in the registry
$regPath2 = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings"
Set-ItemProperty -Path $regPath2 -Name "ShowLockOption" -Value 0 -Type DWord -Force
# Disable sleep option in the registry
Set-ItemProperty -Path $regPath2 -Name "ShowSleepOption" -Value 0 -Type DWord -Force
# Disable fast boot
$regPath3 = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
Set-ItemProperty -Path $regPath3 -Name "HiberbootEnabled" -Value 0 -Type DWord -Force
# Unpark CPU cores
$cpuCoresRegPath = "HKLM:\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583"
Set-ItemProperty -Path $cpuCoresRegPath -Name "ValueMax" -Value 0 -Type DWord -Force
# Disable power throttling
$throttlingRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling"
Set-ItemProperty -Path $throttlingRegPath -Name "PowerThrottlingOff" -Value 1 -Type DWord -Force
# Optimize system responsiveness
$systemProfileRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
Set-ItemProperty -Path $systemProfileRegPath -Name "SystemResponsiveness" -Value 0 -Type DWord -Force
# hard disk turn off hard disk after 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0x00000000
# desktop background settings slide show paused
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 001
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 0d7dbae2-4294-402a-ba8e-26777e8488cd 309dce9b-bef4-4119-9921-a851fb12f0f4 001
# wireless adapter settings power saving mode maximum performance
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 19cbb8fa-5279-450e-9fac-8a3d5fedd0c1 12bbebe6-58d6-4636-95bb-3217ef867c1a 000
# sleep
# sleep after 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0x00000000
# allow hybrid sleep off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 94ac6d29-73ce-41a6-809f-6363ba21b47e 000
# hibernate after
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 9d7815a6-7ee4-497e-8888-515a05f02364 0x00000000
# allow wake timers disable
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 238c9fa8-0aad-41ed-83f4-97be242c8f20 bd3b718a-0680-4d9d-8ab2-e1d2b4ac806d 000
# usb settings usb selective suspend setting disabled
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 000
# power buttons and lid start menu power button shut down
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 002
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 4f971e89-eebd-4455-a8de-9e59040e7347 a7066653-8d6c-40a8-910e-a1f54b84c7e5 002
# pci express link state power management off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 501a4d13-42af-4429-9fd1-a8218c268e20 ee12f906-d277-404b-b6da-e5fa1a576df5 000
# processor power management
# minimum processor state 100%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 893dee8e-2bef-41e0-89c6-b55d0929964c 0x00000064
# system cooling policy active
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 001
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 94d3a615-a899-4ac5-ae2b-e4d8f634367f 001
# maximum processor state 100%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 54533251-82be-4824-96c1-47b60b740d00 bc5038f7-23e0-4960-96da-33abaf5935ec 0x00000064
# display
# turn off display after 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0x00000000
# display brightness 100%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 aded5e82-b909-4619-9949-f5d71dac0bcb 0x00000064
# dimmed display brightness 100%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 f1fbfde2-a960-4165-9f88-50667911ce96 0x00000064
# enable adaptive brightness off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 7516b95f-f776-4464-8c53-06167f40cc99 fbd9aa66-9553-4097-ba44-ed6e9d65eab8 000
# video playback quality bias video playback performance bias
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 10778347-1370-4ee0-8bbd-33bdacaade49 001
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 10778347-1370-4ee0-8bbd-33bdacaade49 001
# when playing video optimize video quality
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 9596fb26-9850-41fd-ac3e-f7c3c00afd4b 34c7b99f-9a6d-4b3c-8dc7-b6693b78cef4 000
# MODIFY LAPTOP SETTINGS
# Intel(R) graphics settings: maximum performance (AC)
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 002 2>&1 > $null
# Intel(R) graphics settings: maximum performance (DC)
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 44f3beca-a7c0-460e-9df2-bb8b99e0cba6 3619c3f2-afb2-4afc-b0e9-e7fef372de36 002 2>&1 > $null
# AMD power slider overlay: best performance (AC)
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 003 2>&1 > $null
# AMD power slider overlay: best performance (DC)
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 c763b4ec-0e50-4b6b-9bed-2b92a6ee884e 7ec1751b-60ed-4588-afb5-9819d3d77d90 003 2>&1 > $null
# ATI graphics power settings: maximize performance (AC)
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 f693fb01-e858-4f00-b20f-f30e12ac06d6 191f65b5-d45c-4a4f-8aae-1ab8bfd980e6 001 2>&1 > $null
# ATI graphics power settings: maximize performance (DC)
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 f693fb01-e858-4f00-b20f-f30e12ac06d6 191f65b5-d45c-4a4f-8aae-1ab8bfd980e6 001 2>&1 > $null
# Switchable dynamic graphics global settings: maximize performance (AC)
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 003 2>&1 > $null
# Switchable dynamic graphics global settings: maximize performance (DC)
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e276e160-7cb0-43c6-b20b-73f5dce39954 a1662ab2-9d34-4e53-ba8b-2639b9e20857 003 2>&1 > $null
# battery
# critical battery notification off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 5dbb7c9f-38e9-40d2-9749-4f8a0e9f640f 000
# critical battery action do nothing
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 637ea02f-bbcb-4015-8e2c-a1c7b9c0b546 000
# low battery level 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 8183ba9a-e910-48da-8769-14ae6dc1170a 0x00000000
# critical battery level 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f 9a66d8d7-4ff7-4ef9-b5a2-5a326ca2a469 0x00000000
# low battery notification off
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f bcded951-187b-4d05-bccc-f7e51960c258 000
# low battery action do nothing
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f d8742dcb-3e6a-4b3c-b3fe-374623cdcf06 000
# reserve battery level 0%
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 e73a048d-bf27-4f12-9731-8b2076e8891f f3c5027d-cd16-4930-aa6b-90db844a8f00 0x00000000
# immersive control panel
# low screen brightness when using battery saver disable
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 de830923-a562-41af-a086-e3a2c6bad2da 13d09884-f74e-474a-a852-b6bde8ad03a8 0x00000064
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 de830923-a562-41af-a086-e3a2c6bad2da 13d09884-f74e-474a-a852-b6bde8ad03a8 0x00000064
# immersive control panel
# turn battery saver on automatically at never
powercfg /setacvalueindex 99999999-9999-9999-9999-999999999999 de830923-a562-41af-a086-e3a2c6bad2da e69653ca-cf7f-4f05-aa73-cb833fa90ad4 0x00000000
powercfg /setdcvalueindex 99999999-9999-9999-9999-999999999999 de830923-a562-41af-a086-e3a2c6bad2da e69653ca-cf7f-4f05-aa73-cb833fa90ad4 0x00000000
Write-Host "Done." 
############################################################################################################################################################
<# Timer Resolution #>
############################################################################################################################################################
Write-Host "Installing: Set Timer Resolution Service"
# create .cs file
$MultilineComment = @"
using System;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.ComponentModel;
using System.Configuration.Install;
using System.Collections.Generic;
using System.Reflection;
using System.IO;
using System.Management;
using System.Threading;
using System.Diagnostics;
[assembly: AssemblyVersion("2.1")]
[assembly: AssemblyProduct("Set Timer Resolution service")]
namespace WindowsService
{
    class WindowsService : ServiceBase
    {
        public WindowsService()
        {
            this.ServiceName = "STR";
            this.EventLog.Log = "Application";
            this.CanStop = true;
            this.CanHandlePowerEvent = false;
            this.CanHandleSessionChangeEvent = false;
            this.CanPauseAndContinue = false;
            this.CanShutdown = false;
        }
        static void Main()
        {
            ServiceBase.Run(new WindowsService());
        }
        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            ReadProcessList();
            NtQueryTimerResolution(out this.MininumResolution, out this.MaximumResolution, out this.DefaultResolution);
            if(null != this.EventLog)
                try { this.EventLog.WriteEntry(String.Format("Minimum={0}; Maximum={1}; Default={2}; Processes='{3}'", this.MininumResolution, this.MaximumResolution, this.DefaultResolution, null != this.ProcessesNames ? String.Join("','", this.ProcessesNames) : "")); }
                catch {}
            if(null == this.ProcessesNames)
            {
                SetMaximumResolution();
                return;
            }
            if(0 == this.ProcessesNames.Count)
            {
                return;
            }
            this.ProcessStartDelegate = new OnProcessStart(this.ProcessStarted);
            try
            {
                String query = String.Format("SELECT * FROM __InstanceCreationEvent WITHIN 0.5 WHERE (TargetInstance isa \"Win32_Process\") AND (TargetInstance.Name=\"{0}\")", String.Join("\" OR TargetInstance.Name=\"", this.ProcessesNames));
                this.startWatch = new ManagementEventWatcher(query);
                this.startWatch.EventArrived += this.startWatch_EventArrived;
                this.startWatch.Start();
            }
            catch(Exception ee)
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Error); }
                    catch {}
            }
        }
        protected override void OnStop()
        {
            if(null != this.startWatch)
            {
                this.startWatch.Stop();
            }

            base.OnStop();
        }
        ManagementEventWatcher startWatch;
        void startWatch_EventArrived(object sender, EventArrivedEventArgs e) 
        {
            try
            {
                ManagementBaseObject process = (ManagementBaseObject)e.NewEvent.Properties["TargetInstance"].Value;
                UInt32 processId = (UInt32)process.Properties["ProcessId"].Value;
                this.ProcessStartDelegate.BeginInvoke(processId, null, null);
            } 
            catch(Exception ee) 
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
                    catch {}

            }
        }
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern IntPtr OpenProcess(UInt32 DesiredAccess, Int32 InheritHandle, UInt32 ProcessId);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern Int32 CloseHandle(IntPtr Handle);
        const UInt32 SYNCHRONIZE = 0x00100000;
        delegate void OnProcessStart(UInt32 processId);
        OnProcessStart ProcessStartDelegate = null;
        void ProcessStarted(UInt32 processId)
        {
            SetMaximumResolution();
            IntPtr processHandle = IntPtr.Zero;
            try
            {
                processHandle = OpenProcess(SYNCHRONIZE, 0, processId);
                if(processHandle != IntPtr.Zero)
                    WaitForSingleObject(processHandle, -1);
            } 
            catch(Exception ee) 
            {
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(ee.ToString(), EventLogEntryType.Warning); }
                    catch {}
            }
            finally
            {
                if(processHandle != IntPtr.Zero)
                    CloseHandle(processHandle); 
            }
            SetDefaultResolution();
        }
        List<String> ProcessesNames = null;
        void ReadProcessList()
        {
            String iniFilePath = Assembly.GetExecutingAssembly().Location + ".ini";
            if(File.Exists(iniFilePath))
            {
                this.ProcessesNames = new List<String>();
                String[] iniFileLines = File.ReadAllLines(iniFilePath);
                foreach(var line in iniFileLines)
                {
                    String[] names = line.Split(new char[] {',', ' ', ';'} , StringSplitOptions.RemoveEmptyEntries);
                    foreach(var name in names)
                    {
                        String lwr_name = name.ToLower();
                        if(!lwr_name.EndsWith(".exe"))
                            lwr_name += ".exe";
                        if(!this.ProcessesNames.Contains(lwr_name))
                            this.ProcessesNames.Add(lwr_name);
                    }
                }
            }
        }
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern int NtSetTimerResolution(uint DesiredResolution, bool SetResolution, out uint CurrentResolution);
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern int NtQueryTimerResolution(out uint MinimumResolution, out uint MaximumResolution, out uint ActualResolution);
        uint DefaultResolution = 0;
        uint MininumResolution = 0;
        uint MaximumResolution = 0;
        long processCounter = 0;
        void SetMaximumResolution()
        {
            long counter = Interlocked.Increment(ref this.processCounter);
            if(counter <= 1)
            {
                uint actual = 0;
                NtSetTimerResolution(this.MaximumResolution, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
                    catch {}
            }
        }
        void SetDefaultResolution()
        {
            long counter = Interlocked.Decrement(ref this.processCounter);
            if(counter < 1)
            {
                uint actual = 0;
                NtSetTimerResolution(this.DefaultResolution, true, out actual);
                if(null != this.EventLog)
                    try { this.EventLog.WriteEntry(String.Format("Actual resolution = {0}", actual)); }
                    catch {}
            }
        }
    }
    [RunInstaller(true)]
    public class WindowsServiceInstaller : Installer
    {
        public WindowsServiceInstaller()
        {
            ServiceProcessInstaller serviceProcessInstaller = 
                               new ServiceProcessInstaller();
            ServiceInstaller serviceInstaller = new ServiceInstaller();
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            serviceProcessInstaller.Username = null;
            serviceProcessInstaller.Password = null;
            serviceInstaller.DisplayName = "Set Timer Resolution Service";
            serviceInstaller.StartType = ServiceStartMode.Automatic;
            serviceInstaller.ServiceName = "STR";
            this.Installers.Add(serviceProcessInstaller);
            this.Installers.Add(serviceInstaller);
        }
    }
}
"@
Set-Content -Path "$env:C:\Windows\SetTimerResolutionService.cs" -Value $MultilineComment -Force
# compile and create service
Start-Process -Wait "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" -ArgumentList "-out:C:\Windows\SetTimerResolutionService.exe C:\Windows\SetTimerResolutionService.cs" -WindowStyle Hidden
# delete file
Remove-Item "$env:C:\Windows\SetTimerResolutionService.cs" -ErrorAction SilentlyContinue | Out-Null
# install and start service
New-Service -Name "Set Timer Resolution Service" -BinaryPathName "$env:C:\Windows\SetTimerResolutionService.exe" -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "Set Timer Resolution Service" -StartupType Automatic -ErrorAction SilentlyContinue | Out-Null
Set-Service -Name "Set Timer Resolution Service" -Status Running -ErrorAction SilentlyContinue | Out-Null
# fix timer resolution regedit
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "GlobalTimerResolutionRequests" /t REG_DWORD /d "1" /f | Out-Null
Write-Host "Done." 
############################################################################################################################################################
<# Registry #>
############################################################################################################################################################
Write-Host "Running Registry Tweaks" 
#----------------
# EASE OF ACCESS
#----------------

# Disable Narrator settings
# Setting to prevent audio feedback from the narrator
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Narrator\NoRoam" -Name "DuckAudio" -Value 0
# Disables the ability to launch Narrator with Win + Enter
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Narrator\NoRoam" -Name "WinEnterLaunchEnabled" -Value 0
# Disable scripting capabilities for the narrator
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Narrator\NoRoam" -Name "ScriptingEnabled" -Value 0
# Disable online services integration for the narrator
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Narrator\NoRoam" -Name "OnlineServicesEnabled" -Value 0
# Disable narrator cursor highlight feature
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Narrator" -Name "NarratorCursorHighlight" -Value 0
# Disable coupling of narrator cursor with keyboard input
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Narrator" -Name "CoupleNarratorCursorKeyboard" -Value 0
# Disable Ease of Access settings
# Disable the self-voice feature in Ease of Access
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Ease of Access" -Name "selfvoice" -Value 0
# Disable self-scan feature in Ease of Access
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Ease of Access" -Name "selfscan" -Value 0
# Disable sound feedback on activation
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility" -Name "Sound on Activation" -Value 0
# Disable warning sounds
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility" -Name "Warning Sounds" -Value 0
# Set High Contrast settings flags (4194 - disabled)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\HighContrast" -Name "Flags" -Value 4194
# Keyboard Response settings
# Set keyboard response flags (2 - disabled)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "Flags" -Value 2
# Disable auto-repeat rate for keyboard
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "AutoRepeatRate" -Value 0
# Disable auto-repeat delay for keyboard
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" -Name "AutoRepeatDelay" -Value 0
# MouseKeys settings
# Set flags for MouseKeys (130 - enabled with specific settings)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "Flags" -Value 130
# Set maximum speed for MouseKeys
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "MaximumSpeed" -Value 39
# Set time to reach maximum speed for MouseKeys
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\MouseKeys" -Name "TimeToMaximumSpeed" -Value 3000
# StickyKeys settings
# Set flags for StickyKeys (2 - enabled)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" -Name "Flags" -Value 2
# ToggleKeys settings
# Set flags for ToggleKeys (34 - enabled)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" -Name "Flags" -Value 34
# SoundSentry settings
# Disable SoundSentry flags
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\SoundSentry" -Name "Flags" -Value 0
# Disable Flash Text Effects in SoundSentry
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\SoundSentry" -Name "FSTextEffect" -Value 0
# Disable Text Effects in SoundSentry
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\SoundSentry" -Name "TextEffect" -Value 0
# Disable Windows Effects in SoundSentry
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\SoundSentry" -Name "WindowsEffect" -Value 0
# SlateLaunch settings
# Clear the ATapp setting
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\SlateLaunch" -Name "ATapp" -Value ""
# Disable automatic launch of Assistive Technology (AT)
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\SlateLaunch" -Name "LaunchAT" -Value 0

#------------------
# CLOCK AND REGION
#------------------

# Disable notification when the clock changes
Set-ItemProperty -Path "HKCU:\Control Panel\TimeDate" -Name "DstNotification" -Value 0 

#--------------------------------
# APPEARANCE AND PERSONALIZATION
#--------------------------------

# Open File Explorer to "This PC"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Value 1 
# Hide frequent folders in Quick Access
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowFrequent" -Value 0 
# Show file name extensions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 
# Disable search history
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDeviceSearchHistoryEnabled" -Value 0 
# Disable showing files from office.com
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "ShowCloudFilesInQuickAccess" -Value 0 
# Disable display of file size information in folder tips
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "FolderContentsInfoTip" -Value 0 
# Enable display of full path in the title bar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Name "FullPath" -Value 1 
# Disable pop-up descriptions for folders and desktop items
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowInfoTip" -Value 0 
# Disable preview handlers in the preview pane
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowPreviewHandlers" -Value 0 
# Disable status bar display
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowStatusBar" -Value 0 
# Disable sync provider notifications
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSyncProviderNotifications" -Value 0 
# Disable the use of the sharing wizard
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "SharingWizardOn" -Value 0 
# Disable showing the network
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{F02C1A0D-BE21-4350-88B0-7367FC96EF3C}" -Name "System.IsPinnedToNameSpaceTree" -Value 0 

#--------------------
# HARDWARE AND SOUND
#--------------------

# Disable lock option in the flyout menu
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowLockOption" -Value 0 
# Disable sleep option in the flyout menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowSleepOption" -Value 0 
# Sound communications do nothing (user ducking preference)
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Multimedia\Audio" -Name "UserDuckingPreference" -Value 3 
# Disable startup sound
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" -Name "DisableStartupSound" -Value 1 
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\EditionOverrides" -Name "UserSetting_DisableStartupSound" -Value 1 
# Set sound scheme to none
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes" -Name "" -Value ".None" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\.Default\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\CriticalBatteryAlarm\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceConnect\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceDisconnect\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\DeviceFail\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\FaxBeep\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\LowBatteryAlarm\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\MailBeep\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\MessageNudge\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Default\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.IM\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Mail\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Proximity\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.Reminder\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\Notification.SMS\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\ProximityConnection\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemAsterisk\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemExclamation\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemHand\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\SystemNotification\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\.Default\WindowsUAC\.Current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\DisNumbersSound\.current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubOffSound\.current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubOnSound\.current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\HubSleepSound\.current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\MisrecoSound\.current" -Name "" -Value "" 
Set-ItemProperty -Path "HKCU:\AppEvents\Schemes\Apps\sapisvr\PanelSound\.current" -Name "" -Value "" 
# Disable autoplay for removable media to prevent automatic actions
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 
# Disable enhanced pointer precision to use a standard mouse speed
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSpeed" -Value "0" 
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0" 
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0" 
# Set mouse pointer scheme to default (none), effectively removing custom pointers
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "AppStarting" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Arrow" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "ContactVisualization" -Value 0 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Crosshair" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "GestureVisualization" -Value 0 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Hand" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Help" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "IBeam" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "No" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "NWPen" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Scheme Source" -Value 0 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "SizeAll" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "SizeNESW" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "SizeNS" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "SizeNWSE" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "SizeWE" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "UpArrow" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "Wait" -Value (0x00, 0x00) 
Set-ItemProperty -Path "HKCU:\Control Panel\Cursors" -Name "" -Value "" 

#---------------------
# NETWORK AND INTERNET
#---------------------

# Prevent device installation settings from accessing device metadata over the network
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Value 1 
# Disable the option for other network users to control or disable the shared internet connection
Set-ItemProperty -Path "HKLM:\System\ControlSet001\Control\Network\SharedAccessConnection" -Name "EnableControl" -Value 0 

#---------------------
# SYSTEM AND SECURITY
#---------------------

# Set visual effects appearance options to custom for better performance
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 3 
# Disable various animations for a smoother user experience
# This includes: 
# - Animate controls and elements inside windows
# - Fade or slide menus into view
# - Fade or slide tooltips into view
# - Fade out menu items after clicking
# - Show shadows under mouse pointer
# - Show shadows under windows
# - Slide open combo boxes
# - Smooth-scroll list boxes
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "UserPreferencesMask" -Value (0x90, 0x12, 0x03, 0x80, 0x10, 0x00, 0x00, 0x00) 
# Disable window animations when minimizing and maximizing
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\WindowMetrics" -Name "MinAnimate" -Value "0" 
# Disable animations in the taskbar for better performance
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAnimations" -Value 0 
# Disable Aero Peek functionality to prevent showing desktop thumbnails
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableAeroPeek" -Value 0 
# Disable saving taskbar thumbnail previews to conserve resources
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "AlwaysHibernateThumbnails" -Value 0 
# Enable showing thumbnails instead of icons in Explorer
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "IconsOnly" -Value 0 
# Disable translucent selection rectangle for better visibility
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewAlphaSelect" -Value 0 
# Disable showing window contents while dragging for a cleaner interface
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "DragFullWindows" -Value "0" 
# Enable smooth edges for screen fonts to improve text clarity
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "FontSmoothing" -Value "2" 
# Disable drop shadows for icon labels on the desktop for a simpler look
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ListviewShadow" -Value 0 
# Adjust system settings for best performance of programs
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\PriorityControl" -Name "Win32PrioritySeparation" -Value 38 
# Disable remote assistance to restrict external help access
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 

#---------------
# TROUBLESHOOTING
#---------------

# Disable automatic maintenance to prevent scheduled maintenance tasks
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" -Name "MaintenanceDisabled" -Value 1 

#---------
# PRIVACY
#---------

# Disable account notifications in the Settings app
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" -Name "EnableAccountNotifications" -Value 0 
# Disable location access for privacy protection
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny" 
# Disable location override setting for user privacy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\UserLocationOverridePrivacySetting" -Name "Value" -Value 0 
# Enable camera access for applications
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" -Name "Value" -Value "Allow" 
# Enable microphone access for applications
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" -Name "Value" -Value "Allow" 
# Disable voice activation for privacy concerns
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -Name "AgentActivationEnabled" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" -Name "AgentActivationLastUsed" -Value 0 
# Disable notifications from user notification listener
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Value "Deny" 
# Disable access to account information for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny" 
# Disable access to contacts for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" -Name "Value" -Value "Deny" 
# Disable access to calendar for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" -Name "Value" -Value "Deny" 
# Disable access to phone calls for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" -Name "Value" -Value "Deny" 
# Disable access to call history for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" -Name "Value" -Value "Deny" 
# Disable access to email for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" -Name "Value" -Value "Deny" 
# Disable access to user tasks for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" -Name "Value" -Value "Deny" 
# Disable access to messaging for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" -Name "Value" -Value "Deny" 
# Disable access to radios for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" -Name "Value" -Value "Deny" 
# Disable access to Bluetooth sync for privacy
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" -Name "Value" -Value "Deny" 
# Disable background apps to save resources
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 
# Disable access to app diagnostics for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny" 
# Disable access to documents for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" -Name "Value" -Value "Deny" 
# Disable access to downloads folder for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" -Name "Value" -Value "Deny" 
# Disable access to music library for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" -Name "Value" -Value "Deny" 
# Disable access to pictures library for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" -Name "Value" -Value "Deny" 
# Disable access to videos library for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" -Name "Value" -Value "Deny" 
# Disable access to file system for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" -Name "Value" -Value "Deny" 
# Disable screenshot borders for a cleaner interface
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" -Name "Value" -Value "Deny" 
# Allow programmatic access to screenshots while restricting other methods
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" -Name "Value" -Value "Allow" 
# Disable access to language list for locally relevant content
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Value 1 
# Disable tracking of app launches to improve start and search results
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Value 1 
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" -Name "DisableMFUTracking" -Value 1 
# Disable personal inking and typing dictionary for privacy
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Value 1 
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Value 1 
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Value 0 
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Value 0 
# Set feedback frequency to never
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "PeriodInNanoSeconds" -Value -1 
# Disable storing activity history on this device for privacy
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Value 0 

#--------
# SEARCH
#--------

# Disable dynamic search box highlights for a cleaner search experience
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsDynamicSearchBoxEnabled" -Value 0 
# Disable safe search to allow all search results
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "SafeSearchMode" -Value 0 
# Disable cloud content search for work or school accounts
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsAADCloudSearchEnabled" -Value 0 
# Disable cloud content search for Microsoft accounts
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SearchSettings" -Name "IsMSACloudSearchEnabled" -Value 0 

#----------------
# EASE OF ACCESS
#----------------

# Disable magnifier settings to prevent following caret, mouse, and focus
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\ScreenMagnifier" -Name "FollowCaret" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\ScreenMagnifier" -Name "FollowNarrator" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\ScreenMagnifier" -Name "FollowMouse" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\ScreenMagnifier" -Name "FollowFocus" -Value 0 
# Disable narrator settings to prevent notifications and echoing of characters and words
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Narrator" -Name "IntonationPause" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Narrator" -Name "ReadHints" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Narrator" -Name "ErrorNotificationType" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Narrator" -Name "EchoChars" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Narrator" -Name "EchoWords" -Value 0 
# Disable auto-start and minimize type for the narrator home
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Narrator\NarratorHome" -Name "MinimizeType" -Value 0 
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Narrator\NarratorHome" -Name "AutoStart" -Value 0 
# Disable echo toggle keys for narrator
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Narrator\NoRoam" -Name "EchoToggleKeys" -Value 0 
# Disable the use of the Print Screen key for opening screen capture
Set-ItemProperty -Path "HKCU:\Control Panel\Keyboard" -Name "PrintScreenKeyForSnippingEnabled" -Value 0 

#--------
# GAMING
#--------

# Disable the Game Bar to prevent its use
Set-ItemProperty -Path "HKCU:\System\GameConfigStore" -Name "GameDVR_Enabled" -Value 0
# Disable app capture feature in Game DVR
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AppCaptureEnabled" -Value 0
# Disable the Xbox Game Bar from opening using the game controller
Set-ItemProperty -Path "HKCU:\Software\Microsoft\GameBar" -Name "UseNexusForGameBarEnabled" -Value 0
# Set audio encoding bitrate for Game DVR
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioEncodingBitrate" -Value 130000
# Disable audio capture in Game DVR
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "AudioCaptureEnabled" -Value 0
# Set custom video encoding bitrate
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CustomVideoEncodingBitrate" -Value 4100000
# Set custom video encoding height
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CustomVideoEncodingHeight" -Value 720
# Set custom video encoding width
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CustomVideoEncodingWidth" -Value 1280
# Set historical buffer length
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "HistoricalBufferLength" -Value 30
# Set historical buffer length unit
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "HistoricalBufferLengthUnit" -Value 1
# Disable historical capture feature
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "HistoricalCaptureEnabled" -Value 0
# Allow historical capture on battery
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "HistoricalCaptureOnBatteryAllowed" -Value 1
# Allow historical capture on wireless display
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "HistoricalCaptureOnWirelessDisplayAllowed" -Value 1
# Set maximum record length
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "MaximumRecordLength" -Value 368640000
# Set video encoding bitrate mode
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VideoEncodingBitrateMode" -Value 2
# Set video encoding resolution mode
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VideoEncodingResolutionMode" -Value 2
# Set video encoding frame rate mode
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VideoEncodingFrameRateMode" -Value 0
# Enable echo cancellation
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "EchoCancellationEnabled" -Value 1
# Disable cursor capture
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "CursorCaptureEnabled" -Value 0
# Disable hotkeys for toggling Game Bar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKToggleGameBar" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKMToggleGameBar" -Value 0
# Disable hotkeys for saving historical video
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKSaveHistoricalVideo" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKMSaveHistoricalVideo" -Value 0
# Disable hotkeys for toggling recording
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKToggleRecording" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKMToggleRecording" -Value 0
# Disable hotkeys for taking screenshots
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKTakeScreenshot" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKMTakeScreenshot" -Value 0
# Disable hotkeys for toggling recording indicator
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKToggleRecordingIndicator" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKMToggleRecordingIndicator" -Value 0
# Disable hotkeys for toggling microphone capture
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKToggleMicrophoneCapture" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKMToggleMicrophoneCapture" -Value 0
# Disable hotkeys for toggling camera capture
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKToggleCameraCapture" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKMToggleCameraCapture" -Value 0
# Disable hotkeys for toggling broadcast
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKToggleBroadcast" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "VKMToggleBroadcast" -Value 0
# Disable microphone capture
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "MicrophoneCaptureEnabled" -Value 0
# Set system audio gain
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "SystemAudioGain" -Value 4294967296
# Set microphone gain
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\GameDVR" -Name "MicrophoneGain" -Value 4294967296

#-----------------
# TIME & LANGUAGE 
#-----------------

# Disable the voice typing microphone button
Set-ItemProperty -Path "HKCU:\Software\Microsoft\input\Settings" -Name "IsVoiceTypingKeyEnabled" -Value 0
# Disable automatic capitalization of the first letter of each sentence
Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "EnableAutoShiftEngage" -Value 0
# Disable audio feedback for key sounds while typing
Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "EnableKeyAudioFeedback" -Value 0
# Disable period addition after double-tapping the spacebar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "EnableDoubleTapSpace" -Value 0
# Disable typing insights feature
Set-ItemProperty -Path "HKCU:\Software\Microsoft\input\Settings" -Name "InsightsEnabled" -Value 0

#----------
# ACCOUNTS
#----------

# Disable the use of sign-in info after a restart
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableAutomaticRestartSignOn" -Value 1

#------
# APPS
#------

# Disable automatic updates for maps
Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Value 0
# Disable automatic archiving of apps
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Appx" -Name "AllowAutomaticAppArchiving" -Value 0

#-----------------
# PERSONALIZATION
#-----------------

# Set a solid color as the background
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Wallpaper" -Value ""
# Set wallpaper type to solid color
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Wallpapers" -Name "BackgroundType" -Value 1
# Enable dark theme for apps and system
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "SystemUsesLightTheme" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "AppsUseLightTheme" -Value 0
# Set accent colors
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" -Name "StartColorMenu" -Value 0xff3d3f41
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" -Name "AccentColorMenu" -Value 0xff484a4c
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Accent" -Name "AccentPalette" -Value 0xDFDEDC00A6A5A100686562004C4A4800413F3D0027252400100D0D00107C1000
# Enable window colorization
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "EnableWindowColorization" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "AccentColor" -Value 0xff484a4c
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorizationColor" -Value 0xc44c4a48
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\DWM" -Name "ColorizationAfterglow" -Value 0xc44c4a48
# Disable transparency effects
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Value 0
# Always hide most used apps in the Start menu
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ShowOrHideMostUsedApps" -Value 2
Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "ShowOrHideMostUsedApps"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList"
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoStartMenuMFUprogramsList"
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoInstrumentation"
# Enable more pinned apps personalization in Start
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_Layout" -Value 1
# Disable recently added apps in Start
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "HideRecentlyAddedApps" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideRecentlyAddedApps" -Value 1
# Disable account-related notifications
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_AccountNotifications" -Value 0
# Disable showing recently opened items in Start, jump lists, and File Explorer
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_TrackDocs" -Value 0
# Align taskbar to the left
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarAl" -Value 1
# Remove Chat from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0
# Remove Task View from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Value 0
# Remove Search from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Value 0
# Remove Windows Widgets from taskbar
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Value 0
# Remove Copilot from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowCopilotButton" -Value 0
# Remove Meet Now from taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HideSCAMeetNow" -Value 1
# Remove Action Center
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Value 0
# Remove News and Interests
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Value 0
# Show all taskbar icons
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Value 0
# Disable dynamic lighting on devices
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Lighting" -Name "AmbientLightingEnabled" -Value 0
# Disable control of lighting by foreground apps
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Lighting" -Name "ControlledByForegroundApp" -Value 0
# Disable matching Windows accent color for lighting
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Lighting" -Name "UseSystemAccentColor" -Value 0
# Disable showing key background
Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\1.7" -Name "IsKeyBackgroundEnabled" -Value 0
# Disable recommendations for tips, shortcuts, new apps, and more
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Start_IrisRecommendations" -Value 0
# Disable sharing any window from the taskbar
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarSn" -Value 0

#---------
# DEVICES
#---------

# Disable notifications for USB issues
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Shell\USB" -Name "NotifyOnUsbErrors" -Value 0
# Disable Windows from managing the default printer
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Windows" -Name "LegacyDefaultPrinterMode" -Value 1
# Disable writing with your fingertip
Set-ItemProperty -Path "HKCU:\Software\Microsoft\TabletTip\EmbeddedInkControl" -Name "EnableInkingWithTouch" -Value 0

#--------
# SYSTEM
#--------

# Set 100% DPI scaling
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "LogPixels" -Value 96
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "Win8DpiScaling" -Value 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\DWM" -Name "UseDpiScaling" -Value 0
# Disable fix scaling for apps
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "EnablePerProcessSystemDPI" -Value 0
# Turn on hardware-accelerated GPU scheduling
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Value 2
# Disable variable refresh rate and enable optimizations for windowed games
Set-ItemProperty -Path "HKCU:\Software\Microsoft\DirectX\UserGpuPreferences" -Name "DirectXUserGlobalSettings" -Value "SwapEffectUpgradeEnable=1;VRROptimizeEnable=0;"
# Disable notifications
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" -Name "Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\windows.immersivecontrolpanel_cw5n1h2txyewy!microsoft.windows.immersivecontrolpanel" -Name "Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.CapabilityAccess" -Name "Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" -Name "Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" -Name "ScoobeSystemSettingEnabled" -Value 0
# Disable suggested actions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" -Name "Disabled" -Value 1
# Disable focus assist
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\??windows.data.notifications.quiethourssettings\Current" -Name "Data" -Value ([byte[]](2,0,0,0,180,103,43,104,240,11,216,1,0,0,0,0,67,66,1,0,194,10,1,210,20,40,77,0,105,0,99,0,114,0,111,0,115,0,111,0,102,0,116,0,46,0,81,0,117,0,105,0,101,0,116,0,72,0,111,0,117,0,114,0,115,0,80,0,114,0,111,0,102,0,105,0,108,0,101,0,46,0,85,0,110,0,114,0,101,0,115,0,116,0,114,0,105,0,99,0,116,0,101,0,100,0,202,40,208,20,2,0,0))
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentfullscreen?windows.data.notifications.quietmoment\Current" -Name "Data" -Value ([byte[]](2,0,0,0,151,29,45,104,240,11,216,1,0,0,0,0,67,66,1,0,194,10,1,210,30,38,77,0,105,0,99,0,114,0,111,0,115,0,111,0,102,0,116,0,46,0,81,0,117,0,105,0,101,0,116,0,72,0,111,0,117,0,114,0,115,0,80,0,114,0,111,0,102,0,105,0,108,0,101,0,46,0,65,0,108,0,97,0,114,0,109,0,115,0,79,0,110,0,108,0,121,0,194,40,1,202,80,0,0))
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentgame?windows.data.notifications.quietmoment\Current" -Name "Data" -Value ([byte[]](2,0,0,0,108,57,45,104,240,11,216,1,0,0,0,0,67,66,1,0,194,10,1,210,30,40,77,0,105,0,99,0,114,0,111,0,115,0,111,0,102,0,116,0,46,0,81,0,117,0,105,0,101,0,116,0,72,0,111,0,117,0,114,0,115,0,80,0,114,0,111,0,102,0,105,0,108,0,101,0,46,0,80,0,114,0,105,0,111,0,114,0,105,0,116,0,121,0,79,0,110,0,108,0,121,0,194,40,1,202,80,0,0))
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentpostoobe?windows.data.notifications.quietmoment\Current" -Name "Data" -Value ([byte[]](2,0,0,0,6,84,45,104,240,11,216,1,0,0,0,0,67,66,1,0,194,10,1,210,30,40,77,0,105,0,99,0,114,0,111,0,115,0,111,0,102,0,116,0,46,0,81,0,117,0,105,0,101,0,116,0,72,0,111,0,117,0,114,0,115,0,80,0,114,0,111,0,102,0,105,0,108,0,101,0,46,0,80,0,114,0,105,0,111,0,114,0,105,0,116,0,121,0,79,0,110,0,108,0,121,0,194,40,1,202,80,0,0))
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentpresentation?windows.data.notifications.quietmoment\Current" -Name "Data" -Value ([byte[]](2,0,0,0,131,110,45,104,240,11,216,1,0,0,0,0,67,66,1,0,194,10,1,210,30,26,77,0,105,0,99,0,114,0,111,0,115,0,111,0,102,0,116,0,46,0,81,0,117,0,105,0,101,0,116,0,72,0,111,0,117,0,114,0,115,0,80,0,114,0,111,0,102,0,105,0,108,0,101,0,46,0,65,0,108,0,97,0,114,0,109,0,115,0,79,0,110,0,108,0,121,0,194,40,1,202,80,0,0))
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\?quietmomentscheduled?windows.data.notifications.quietmoment\Current" -Name "Data" -Value ([byte[]](2,0,0,0,46,138,

#----------
# UWP APPS
#----------

# Disable Windows Input Experience preload
Set-ItemProperty -Path "HKCU:\Software\Microsoft\input" -Name "IsInputAppPreloadEnabled" -Value 0
# Disable DSH prelaunch
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Dsh" -Name "IsPrelaunchEnabled" -Value 0
# Disable web search in Start menu
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Value 1
# Disable Windows Copilot
Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Value 1
# Disable Widgets
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" -Name "value" -Value 0

#--------
# NVIDIA
#--------

# Disable NVIDIA tray icon
Set-ItemProperty -Path "HKCU:\Software\NVIDIA Corporation\NvTray" -Name "StartOnLogin" -Value 0
# Enable old NVIDIA sharpening
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\FTS" -Name "EnableGR535" -Value 0

#----------
# GRAPHICS
#----------

# Enable MPO (Multi Plane Overlay)
Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Dwm" -Name "OverlayTestMode"
# Configure games scheduling for performance
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Affinity" -Value 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Background Only" -Value "False"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Clock Rate" -Value 10000
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "GPU Priority" -Value 8
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Priority" -Value 6
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "Scheduling Category" -Value "High"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" -Name "SFIO Priority" -Value "High"

#-------
# POWER
#-------

# Unpark CPU cores
Set-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Control\Power\PowerSettings\54533251-82be-4824-96c1-47b60b740d00\0cc5b647-c1df-4637-891a-dec35c318583" -Name "ValueMax" -Value 0
# Disable power throttling
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" -Name "PowerThrottlingOff" -Value 1
# Configure network throttling & system responsiveness
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "NetworkThrottlingIndex" -Value 0xffffffff
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" -Name "SystemResponsiveness" -Value 0
# Disable hibernate
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabled" -Value 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name "HibernateEnabledDefault" -Value 0
# Disable fast boot
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Value 0
# Fix timer resolution
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" -Name "GlobalTimerResolutionRequests" -Value 1

#-----------------------------------
# DISABLE ADVERTISING & PROMOTIONAL
#-----------------------------------

# Disable content delivery
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Value 0
# Disable feature management
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "FeatureManagementEnabled" -Value 0
# Disable OEM pre-installed apps
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Value 0
# Disable pre-installed apps
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Value 0
# Disable rotating lock screen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenEnabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "RotatingLockScreenOverlayEnabled" -Value 0
# Disable silent installed apps
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Value 0
# Disable slideshow on lock screen
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SlideshowEnabled" -Value 0
# Disable soft landing for apps
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SoftLandingEnabled" -Value 0
# Disable subscribed content
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-314563Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338393Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353694Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353696Enabled" -Value 0
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Value 0
# Disable general subscribed content
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContentEnabled" -Value 0
# Disable system pane suggestions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Value 0

#-------
# OTHER
#-------

# Remove 3D Objects from This PC
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force
Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Force
# Remove Quick Access from File Explorer
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "HubMode" -Value 1
# Remove Home from Desktop
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_36354489\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" -Force
# Remove Gallery from Desktop
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace_41040327\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" -Force
# Restore the classic context menu
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" -Name "(default)" -Value ""
# Disable menu show delay
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name "MenuShowDelay" -Value "0"
# Disable driver searching & updates
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Value 0
# Mouse fix settings
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "MouseSensitivity" -Value "10"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseXCurve" -Value ([byte[]](0,0,0,0,0,0,0,0,192,204,12,0,0,0,0,0,128,153,25,0,0,0,0,0,64,102,38,0,0,0,0,0))
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" -Name "SmoothMouseYCurve" -Value ([byte[]](0,0,0,0,0,0,0,0,0,0,56,0,0,0,0,0,0,0,112,0,0,0,0,0,0,0,168,0,0,0,0,0,0,0,224,0,0,0,0,0))
Set-ItemProperty -Path "HKU\.DEFAULT\Control Panel\Mouse" -Name "MouseSpeed" -Value "0"
Set-ItemProperty -Path "HKU\.DEFAULT\Control Panel\Mouse" -Name "MouseThreshold1" -Value "0"
Set-ItemProperty -Path "HKU\.DEFAULT\Control Panel\Mouse" -Name "MouseThreshold2" -Value "0"
# Disable ConfirmFileDelete
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "ConfirmFileDelete" -Type DWord -Value 1

Write-Host "Done."
############################################################################################################################################################
<# C++ Installation #>
############################################################################################################################################################
Write-Host "Installing C++ for running applications" 

    function Get-FileFromWeb {
    param ([Parameter(Mandatory)][string]$URL, [Parameter(Mandatory)][string]$File)
    function Show-Progress {
    param ([Parameter(Mandatory)][Single]$TotalValue, [Parameter(Mandatory)][Single]$CurrentValue, [Parameter(Mandatory)][string]$ProgressText, [Parameter()][int]$BarSize = 10, [Parameter()][switch]$Complete)
    $percent = $CurrentValue / $TotalValue
    $percentComplete = $percent * 100
    if ($psISE) { Write-Progress "$ProgressText" -id 0 -percentComplete $percentComplete }
    else { Write-Host -NoNewLine "`r$ProgressText $(''.PadRight($BarSize * $percent, [char]9608).PadRight($BarSize, [char]9617)) $($percentComplete.ToString('##0.00').PadLeft(6)) % " }
    }
    try {
    $request = [System.Net.HttpWebRequest]::Create($URL)
    $response = $request.GetResponse()
    if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) { throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'." }
    if ($File -match '^\.\\') { $File = Join-Path (Get-Location -PSProvider 'FileSystem') ($File -Split '^\.')[1] }
    if ($File -and !(Split-Path $File)) { $File = Join-Path (Get-Location -PSProvider 'FileSystem') $File }
    if ($File) { $fileDirectory = $([System.IO.Path]::GetDirectoryName($File)); if (!(Test-Path($fileDirectory))) { [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null } }
    [long]$fullSize = $response.ContentLength
    [byte[]]$buffer = new-object byte[] 1048576
    [long]$total = [long]$count = 0
    $reader = $response.GetResponseStream()
    $writer = new-object System.IO.FileStream $File, 'Create'
    do {
    $count = $reader.Read($buffer, 0, $buffer.Length)
    $writer.Write($buffer, 0, $count)
    $total += $count
    if ($fullSize -gt 0) { Show-Progress -TotalValue $fullSize -CurrentValue $total -ProgressText " $($File.Name)" }
    } while ($count -gt 0)
    }
    finally {
    $reader.Close()
    $writer.Close()
    }
    }
# download c++ installers
Get-FileFromWeb -URL "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE" -File "$env:TEMP\vcredist2005_x86.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE" -File "$env:TEMP\vcredist2005_x64.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe" -File "$env:TEMP\vcredist2008_x86.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe" -File "$env:TEMP\vcredist2008_x64.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe" -File "$env:TEMP\vcredist2010_x86.exe" 
Get-FileFromWeb -URL "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe" -File "$env:TEMP\vcredist2010_x64.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe" -File "$env:TEMP\vcredist2012_x86.exe"
Get-FileFromWeb -URL "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe" -File "$env:TEMP\vcredist2012_x64.exe"
Get-FileFromWeb -URL "https://aka.ms/highdpimfc2013x86enu" -File "$env:TEMP\vcredist2013_x86.exe"
Get-FileFromWeb -URL "https://aka.ms/highdpimfc2013x64enu" -File "$env:TEMP\vcredist2013_x64.exe"
Get-FileFromWeb -URL "https://aka.ms/vs/17/release/vc_redist.x86.exe" -File "$env:TEMP\vcredist2015_2017_2019_2022_x86.exe"
Get-FileFromWeb -URL "https://aka.ms/vs/17/release/vc_redist.x64.exe" -File "$env:TEMP\vcredist2015_2017_2019_2022_x64.exe"
# start c++ installers
Start-Process -wait "$env:TEMP\vcredist2005_x86.exe" -ArgumentList "/q"
Start-Process -wait "$env:TEMP\vcredist2005_x64.exe" -ArgumentList "/q"
Start-Process -wait "$env:TEMP\vcredist2008_x86.exe" -ArgumentList "/qb"
Start-Process -wait "$env:TEMP\vcredist2008_x64.exe" -ArgumentList "/qb"
Start-Process -wait "$env:TEMP\vcredist2010_x86.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2010_x64.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2012_x86.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2012_x64.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2013_x86.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2013_x64.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2015_2017_2019_2022_x86.exe" -ArgumentList "/passive /norestart"
Start-Process -wait "$env:TEMP\vcredist2015_2017_2019_2022_x64.exe" -ArgumentList "/passive /norestart"
Write-Host "Done." 
############################################################################################################################################################
<# Direct X Installation #>
############################################################################################################################################################
Write-Host "Installing DirectX" 
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
Write-Host "Done." 
############################################################################################################################################################
<# Cleanup #>
############################################################################################################################################################
Write-Host "Running Cleanup" 
# clear %temp% folder
Remove-Item -Path "$env:USERPROFILE\AppData\Local\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:USERPROFILE\AppData\Local" -Name "Temp" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
<# # open %temp% folder
Start-Process $env:TEMP #>
# clear temp folder
Remove-Item -Path "$env:C:\Windows\Temp" -Recurse -Force -ErrorAction SilentlyContinue | Out-Null
New-Item -Path "$env:C:\Windows" -Name "Temp" -ItemType Directory -ErrorAction SilentlyContinue | Out-Null
Write-Host "Done." 
Write-Host "Restart your computer for settings to take effect."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
############################################################################################################################################################
<# Run Titus Script #>
############################################################################################################################################################
#iwr -useb "https://christitus.com/win" | iex
<#
# open temp folder
Start-Process $env:C:\Windows\Temp
# open disk cleanup
Start-Process cleanmgr.exe
<# 
############################################################################################################################################################
 Remove Bloatware
############################################################################################################################################################
Get-AppxPackage -allusers Clipchamp.Clipchamp | Remove-AppxPackage
Get-AppxPackage -allusers Disney.37853FC22B2CE | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.BingNews | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.BingWeather | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.GetHelp | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.Getstarted | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.MSPaint | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.Microsoft3DViewer | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.MicrosoftOfficeHub | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.MicrosoftSolitaireCollection | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.MicrosoftStickyNotes | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.MixedReality.Portal | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.Office.OneNote | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.OneDriveSync | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.People | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.PowerAutomateDesktop | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.ScreenSketch | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.SkypeApp | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.Todos | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.Wallet | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.WindowsAlarms | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.WindowsCalculator | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.WindowsCamera | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.WindowsFeedbackHub | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.WindowsMaps | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.WindowsSoundRecorder | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.YourPhone | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.ZuneMusic | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.ZuneVideo | Remove-AppxPackage
Get-AppxPackage -allusers MicrosoftCorporationII.QuickAssist | Remove-AppxPackage
Get-AppxPackage -allusers MicrosoftTeams | Remove-AppxPackage
Get-AppxPackage -allusers MicrosoftWindows.Client.WebExperience | Remove-AppxPackage
Get-AppxPackage -allusers SpotifyAB.SpotifyMusic | Remove-AppxPackage
Get-AppxPackage -allusers Microsoft.WindowsCommunicationsApps | Remove-AppxPackage
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
############################################################################################################################################################
 Personal Programs
############################################################################################################################################################
Write-Output "Installing Chocolatey"
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
choco install chocolatey-core.extension -y
Write-Output "Installing Personal Applications"
choco install peazip -y
choco install vlc -y
choco install notepadplusplus -y
choco install thorium -y
choco install discord -y
choco install steam -y
rustdesk
dolby atmos
syncthing
vscode
nvcleaninstall
ddu
fiio
equlizerapo
peacegui
autodesk fusion
rustdesk
konversation
sunshine
spotify
tor
davinci resolve
 #>