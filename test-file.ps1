function Enable-GameMode {
    $gameModePath = "HKCU:\SOFTWARE\Microsoft\GameBar"
    
    # Check if the path exists, create it if it doesn't
    if (-not (Test-Path $gameModePath)) {
        New-Item -Path $gameModePath -Force
    }
    
    # Set or create properties
    New-ItemProperty -Path $gameModePath -Name "AutoGameModeEnabled" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $gameModePath -Name "UseGameMode" -Value 1 -PropertyType DWord -Force
    
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
