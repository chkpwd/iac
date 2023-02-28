Start-Transcript -Path C:\Automation\Packer\ResetWinRM.log -Force

try {

  # Disallow unencrypted WinRM traffic
  Write-Output "`nDisallowing unencrypted WinRM traffic."
  winrm set winrm/config/service '@{AllowUnencrypted="false"}'

	# Disllow WinRM on public networks.
  # Disabled because public network profile is irrelevant for servers.
  # Write-Output "`nDisallowing WinRM on public networks."
	# Set-NetFirewallRule -Name 'WINRM-HTTP-In-TCP-PUBLIC' -RemoteAddress LocalSubnet4

}
catch {
  Write-Output "Error: $($_.Exception.Message)"
}
finally {
  Stop-Transcript
}
