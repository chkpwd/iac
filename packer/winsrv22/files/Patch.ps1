$logDir = 'C:\Automation\Packer'
If (-not (Test-Path $logDir)) {

  Write-Output "`nCreating log directory ($logDir).`n"
  New-Item -ItemType Directory -Path $logDir -Force | Out-Null

}

Start-Transcript "$logDir\PackerBuild.log" -Force

$ErrorActionPreference = "Stop"

# Install PSWindowsUpdate Module
Write-Output "`nInstalling Nuget package provider."
Get-PackageProvider -name Nuget -Force | Out-Null

Write-Output "`nInstalling PSWindowsUpdate Module."
Install-Module PSWindowsUpdate -confirm:$false -Force

# Install updates
Write-Output "`nInstalling updates - Logging to $logDir\WindowsUpdate.log"

Get-WindowsUpdate -MicrosoftUpdate -Install -IgnoreUserInput -AcceptAll -IgnoreReboot | Out-File -FilePath "$logDir\WindowsUpdate.log" -Append

# Run again to catch any missed updates
Get-WindowsUpdate -MicrosoftUpdate -Install -IgnoreUserInput -AcceptAll -IgnoreReboot | Out-File -FilePath "$logDir\WindowsUpdate.log" -Append

# And again to catch drivers - This cmdlet has shown a little more success in that regard.
Get-WUList -MicrosoftUpdate -Install -AcceptAll -IgnoreReboot | Out-File -FilePath "$logDir\WindowsUpdate.log" -Append
