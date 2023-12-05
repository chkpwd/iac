Write-Host "Cleaning updates.."
Stop-Service -Name wuauserv -Force
Remove-Item C:\Windows\SoftwareDistribution\Download\* -Recurse -Force
Start-Service -Name wuauserv

# Get OS version
$osVersion = (Get-WmiObject -Class Win32_OperatingSystem).Version

# Check if the OS is not Windows 11
if ($osVersion -notlike "10.0.22000.*") {
    Write-Host "Cleaning Component Store"
    Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
} else {
    Write-Host "OS is Windows 11, skipping DISM Component Store cleanup."
}
