Start-Transcript C:\Automation\Packer\Sysprep.log

try {

  Write-Output "`nTidying up sysprep file(s) and process(es)"

  If ( Test-Path $Env:SystemRoot\system32\Sysprep\unattend.xml ) {
    Remove-Item $Env:SystemRoot\system32\Sysprep\unattend.xml -Force
  }

  If ( Get-Process -Name 'Sysprep' -ErrorAction SilentlyContinue ) {
    Stop-Process -Name 'Sysprep' -Force -ErrorAction SilentlyContinue
  }

  # Disable audit mode on next boot
  Write-Output "`nDisabling audit mode on next boot."

  $Path = 'HKLM:\SYSTEM\Setup\Status'
  $Name = 'AuditBoot'
  $Value = 0

  if (Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue) {
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWORD -Force
  }
  else {
    New-ItemProperty -Path $Path -Name $Name -Value $Value -Type DWORD -Force
  }


  # Get Packer CD drive letter
  $packerCd = (Get-Volume -FriendlyName 'packer').DriveLetter

  Write-Output "`nRunning sysprep."

  try {

    # use /quit instead of /shutdown to sysprep without shutdown
    # omitting /shutdown alone will not stop shutdown; this is default behaviour
    & $env:SystemRoot\System32\Sysprep\Sysprep.exe /oobe /generalize /shutdown /unattend:"$($packerCd):\Unattend-Sysprep.xml" /quiet
  }
  catch {

    Write-Output "`nSysprep failed:"
    Write-Output $_
    exit 1

  }

  Write-Output "`nSysprep executed."
}
catch {

  Write-Output "`nSysprep failed:"
  Write-Output $_
  exit 1

}
finally {
  Stop-Transcript
}
