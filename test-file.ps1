# Enable Game Mode in Windows 10/11

# Import the required module
Import-Module -Name GameMode -ErrorAction Stop

# Check if the Game Mode is available
if (-not (Get-Command Enable-GameMode -ErrorAction SilentlyContinue)) {
    Write-Host "Game Mode is not available on this system." -ForegroundColor Red
    exit
}

# Enable Game Mode
Enable-GameMode
Write-Host "Game Mode has been enabled." -ForegroundColor Green