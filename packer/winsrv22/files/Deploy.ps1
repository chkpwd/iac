function Set-RegistryKey
{
    param(
        [string]$Path,
        [string]$Key,
        [int]$Value
    )
    if (-not (Test-Path $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }
		if (Get-ItemProperty -Path $Path -Name $Key -ErrorAction SilentlyContinue) {
			Set-ItemProperty -Path $Path -Name $Key -Value $Value -Type DWORD -Force | Out-Null
		}
		else {
			New-ItemProperty -Path $Path -Name $Key -Value $Value -Type DWORD -Force | Out-Null
		}
}

try {
	Write-Output "`nExecuting first-time deployment script."

	$logDir = 'C:\Automation\Packer'
	If (-not (Test-Path $logDir)) {
		Write-Output "`nCreating log directory ($logDir).`n"
		New-Item -ItemType Directory -Path $logDir -Force | Out-Null
	}

	Start-Transcript "$logDir\PackerDeploy.log" -Force

	$ErrorActionPreference = "Stop"


	# Determine if running on Server Core
	$regKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
	$core = (Get-ItemProperty $regKey).InstallationType -eq "Server Core"

	If ($core) {
		Write-Output "`nRunning on Windows Server Core.`n"
	}
	else {
		Write-Output "`nRunning on Windows Server with Desktop Experience.`n"
	}



	# Set High-perf powerprofile if not laptop type
	If (-not (Get-CimInstance -ClassName Win32_battery)) {
		Write-Output "`nSetting High Performance power profile."

		$HighPerf = powercfg -l | ForEach-Object { if($_.contains("High performance")) {$_.split()[3]} }

		# $HighPerf cannot be $null, we try activate this power profile with powercfg
		if ($null -eq $HighPerf)
		{
			throw "Error: HighPerf is null"
		}

		$CurrPlan = $(powercfg -getactivescheme).split()[3]

		if ($CurrPlan -ne $HighPerf) {powercfg -setactive $HighPerf}
	}

	# Enable network discovery
	Write-Output "`nEnabling network discovery..."
	netsh advfirewall firewall set rule group="Network Discovery" new enable=Yes
	If (-not $?) {
		throw
	}

	# Disable Edge update task
	Write-Output "`nDisabling Edge update task."
	try {
		Get-ScheduledTask -TaskName MicrosoftEdgeUpdateTaskMachine* | Stop-ScheduledTask | Out-Null
		Get-ScheduledTask -TaskName MicrosoftEdgeUpdateTaskMachine* | Disable-ScheduledTask | Out-Null
	}
	catch {
		Write-Output "`nEdge update task not found."
	}

	# Reset auto logon count
	# https://docs.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-shell-setup-autologon-logoncount#logoncount-known-issue
	Write-Output "`nResetting auto logon count."
	Set-RegistryKey -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Key 'AutoLogonCount' -Value '0'

	# If Windows Server Core...
	If ($core) {

		# Disable sconfig on login
		Write-Output "`nDisabling sconfig start on login."
		Set-SConfig -AutoLaunch $false -AllUsers

	}

	# Create RunOnce regkey to set network connection profile to private on next boot
	Write-Output "`nCreating RunOnce regkey to set network connection profile to private on next boot."
  $runOnceRegKey = @{
    Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
    Name = '!NetConnectionProfile'
    PropertyType = 'String'
    Value = 'powershell.exe -NoProfile -NonInteractive -Command "Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private"'
  }
  New-ItemProperty @runOnceRegKey -Force | Out-Null

	# Configure OpenSSH
	Write-Output "`nConfiguring Win32-OpenSSH..."

	## Delete host keys
	Write-Output "`nRemoving SSH host keys."
	Remove-Item $env:ProgramData\ssh\ssh_host_*_key* -Force

	## Generate new host keys
	Write-Output "`nGenerating new SSH host keys..."
	& $env:ProgramFiles\OpenSSH\ssh-keygen -A

	## Fix host key file permissions
	Write-Output "`nFixing host file permissions..."
	& $env:ProgramFiles\OpenSSH\FixHostFilePermissions.ps1 -Confirm:$false

	Write-Output "`nCOMPLETED SUCCESSFULLY.`n"


	# Reboot regardless of requirement; this is a workaround for an
	# issue where the machine starts in audit mode. Most likely bad configuration somewhere.
	Write-Output "`nRebooting in 30 seconds...`n"
	$seconds = 30;
	1..$seconds | ForEach-Object {
		$percent = $_ * 100 / $seconds; 
		Write-Progress -Activity 'Reboot Countdown' -Status "Rebooting in $($seconds - $_) seconds..." -PercentComplete $percent -SecondsRemaining $($seconds - $_)
		Start-Sleep -Seconds 1
	}
	Restart-Computer

}
catch {
	Write-Output "Error: $($_.Exception.Message)"
	Write-Output "`nExiting in 90 seconds...`n"

	Start-Sleep -Seconds 90
}
finally {
	Stop-Transcript
}
