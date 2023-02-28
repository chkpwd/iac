# Create RunOnce regkey to run at next startup. The task will run
# a script which disallows unencrypted WinRM traffic, then disables
# the task and deletes itself.

Start-Transcript -Path 'C:\Automation\Packer\ResetWinRM-Task.log' -Force

try {

  $runOnceRegKey = @{
    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    Name = '!WinRM-NoUnencrypted'
    PropertyType = 'String'
    Value = 'powershell.exe -File "C:\Automation\Packer\ResetWinRM.ps1"'
  }
  New-ItemProperty @runOnceRegKey -Force

}
catch {
  Write-Output "Error: $($_.Exception.Message)"
}
finally {
  Stop-Transcript
}
