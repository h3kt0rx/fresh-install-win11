function Enable-GameMode {
    $gameModePath = "HKLM:\SOFTWARE\Microsoft\GameBar"
    
    # Check if the path exists, create it if it doesn't
    if (-not (Test-Path $gameModePath)) {
        New-Item -Path $gameModePath -Force
    }
    
    # Set or create properties
    New-ItemProperty -Path $gameModePath -Name "AutoGameModeEnabled" -Value 1 -PropertyType DWord -Force
    New-ItemProperty -Path $gameModePath -Name "UseGameMode" -Value 1 -PropertyType DWord -Force
    
    Write-Host "Game Mode has been enabled."
}

# Run the function with administrative privileges
Enable-GameMode
