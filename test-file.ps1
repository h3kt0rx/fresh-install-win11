# Function to Enable Game Mode
function Enable-GameMode {
    $gameModePath = "HKLM:\SOFTWARE\Microsoft\GameBar"
    if (-not (Test-Path $gameModePath)) {
        New-Item -Path $gameModePath -Force
    }
    Set-ItemProperty -Path $gameModePath -Name "AutoGameModeEnabled" -Value 1 -ErrorAction SilentlyContinue
#    Set-ItemProperty -Path $gameModePath -Name "UseGameMode" -Value 1 -ErrorAction SilentlyContinue
    Write-Host "Game Mode has been enabled."
}

# Function to Disable Core Isolation Memory Integrity
function Disable-CoreIsolation {
    $memoryIntegrityPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceGuard"
    
    if (-not (Test-Path $memoryIntegrityPath)) {
        New-Item -Path $memoryIntegrityPath -Force
    }

    # Set Memory Integrity to disabled
    Set-ItemProperty -Path $memoryIntegrityPath -Name "EnableVirtualizationBasedSecurity" -Value 0 -ErrorAction SilentlyContinue
    Write-Host "Core Isolation Memory Integrity has been disabled."
}

# Execute Optimization Functions
Disable-CoreIsolation
Enable-GameMode