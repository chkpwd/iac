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

	Write-Output "`nExecuting build script."

	$logDir = 'C:\Automation\Packer'
	If (-not (Test-Path $logDir)) {

		Write-Output "`nCreating log directory ($logDir).`n"
		New-Item -ItemType Directory -Path $logDir -Force | Out-Null

	}

	Start-Transcript "$logDir\PackerBuild.log" -Force

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

	# Disable Windows Error Reporting
	Write-Output "`nDisabling Windows Error Reporting."
	Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Key "Disable" -Value "1"

	# Disable telemetry
	Write-Output "`nDisabling/reducing some telemetry."
	Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Key "AllowTelemetry" -Value "0"
	Set-Service -Name "DiagTrack" -StartupType Disabled
	If ( -not $core ) { Set-Service -Name "dmwappushservice" -StartupType Disabled }


	# If Windows Server GUI
	If (-not $core) {

		# Pin apps to taskbar & clear Start Menu pins
		Write-Output "`nSetting start layout & taskbar pins."
		Import-StartLayout -LayoutPath "A:\TaskbarLayout.xml" -MountPath "C:\"

		# Create PSDrive for HKU
		Write-Output "`nCreating 'HKU' PSDrive for 'HKEY_USERS'."
		New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null

		# Load default user hive
		Write-Output "`nLoading default user hive..."
		reg load HKU\DefaultUser "C:\Users\Default\NTUSER.DAT"
		If (-not $?) {
			throw
		}

		# Advertising ID
		Write-Output "`nDisabling Advertising ID."
		Set-RegistryKey -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Key "Enabled" -Value "1" | Out-Null

		# Disable Server Manager on login
		Write-Output "`nDisabling Server Manager start on login"
		## machine
		Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Key "DoNotOpenServerManagerAtLogon" -Value "1" | Out-Null
		Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\ServerManager\Oobe" -Key "DoNotOpenInitialConfigurationTasksAtLogon" -Value "1" | Out-Null

		# Disable Server Manager Windows Admin Centre pop-up
		Write-Output "`nDisabling Server Manager Windows Admin Centre pop-up."
		Set-RegistryKey -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Key "DoNotPopWACConsoleAtSMLaunch" -Value "1" | Out-Null

		# Disable new network window
		Write-Output "`nDisabling new network window."
		New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff -Force | Out-Null

		# Show known file extensions
		Write-Output "`nExplorer show known file extensions."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Key "HideFileExt" -Value "0" | Out-Null

		# Show hidden files
		Write-Output "`nExplorer show hidden files."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Key "Hidden" -Value "1" | Out-Null

		# Change default explorer view to this pc
		Write-Output "`nExplorer change default view to This PC."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Key "LaunchTo" -Value "1" | Out-Null

		# Hide search box & icon on the taskbar
		Write-Output "`nHiding search box & icon on the taskbar."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" -Key "SearchboxTaskbarMode" -Value "0" | Out-Null

		# Show ribbon in File Explorer
		Write-Output "`nExplorer default show control ribbon."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" -Key "ExplorerRibbonStartsMinimized" -Value "2" | Out-Null

		# Always show all icons and notifications on the taskbar
		# https://winaero.com/blog/always-show-tray-icons-windows-10
		Write-Output "`nAlways show all icons and notifications on the taskbar."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer" -Key "EnableAutoTray" -Value "0" | Out-Null

		# Optimizes Explorer and Start Menu responses Times
		# https://docs.citrix.com/en-us/workspace-environment-management/current-release/reference/environmental-settings-registry-values.html
		Write-Output "`nOptimizing Explorer and Start Menu responses times."
		Set-RegistryKey -Path "HKU:\DefaultUser\Control Panel\Desktop" -Key "InteractiveDelay" -Value "40" | Out-Null

		# Expand to open folder
		Write-Output "`nExplorer always expand to open folder."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Key "NavPaneExpandToCurrentFolder" -Value "1" | Out-Null

		# Display full path in title bar
		Write-Output "`nExplorer display full path in title bar."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\CabinetState" -Key "FullPath" -Value "1" | Out-Null

		# Remove "Recently added" list from Start Menu
		Write-Output "`nRemoving 'Recently added' list from Start Menu."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" -Key "HideRecentlyAddedApps" -Value "1" | Out-Null

		# Enable dark mode
		Write-Output "`nEnabling dark mode."
		Set-RegistryKey -Path "HKU:\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Key "AppsUseLightTheme" -Value "0" | Out-Null

		# Remove HKU PSDrive
		Write-Output "`nRemoving HKU PSDrive."
		Remove-PSDrive -Name HKU -Force -ErrorAction SilentlyContinue | Out-Null

		<#
		Unload default user hive

		https://jrich523.wordpress.com/2012/03/06/powershell-loading-and-unloading-registry-hives/
		https://social.technet.microsoft.com/Forums/en-US/78efe17d-1faa-4da1-a0e2-3387493a1e97/powershell-loading-unloading-and-reading-hku?forum=ITCG
		#>
		[gc]::collect()

		Write-Output "`nUnloading default user hive..."
		reg unload HKU\DefaultUser
		If (-not $?) {
			$repeat = 0
			$regFail = $true
			while ($regFail -and $repeat -lt 10) {
				$repeat++
				Start-Sleep -Seconds 2
				Write-Output "`nUnloading default user hive failed. Retrying..."
				reg unload HKU\DefaultUser
				If ($?) {
					$regFail = $false
				}
			}
			If ($regFail) {
				Write-Output "`nUnloading default user hive failed after 10 retries. Exiting."
				throw
			}
		}

	}

	# Set timezone
	Write-Output "`nSetting timezone to EST."
	Set-TimeZone -Id 'Eastern Standard Time'

	# Compile DotNet Assemblies
	Start-Process -FilePath C:\windows\microsoft.net\framework\v4.0.30319\ngen.exe -ArgumentList 'update /force /queue'
	Start-Process -FilePath C:\windows\microsoft.net\framework64\v4.0.30319\ngen.exe -ArgumentList 'update /force /queue'
	Start-Process -FilePath C:\windows\microsoft.net\framework\v4.0.30319\ngen.exe -ArgumentList 'executequeueditems'
	Start-Process -FilePath C:\windows\microsoft.net\framework64\v4.0.30319\ngen.exe -ArgumentList 'executequeueditems'
} catch {

	Write-Output "Error: $($_.Exception.Message)"
	Write-Output "Exiting in 90 seconds...`n"

  Start-Sleep -Seconds 90

  Exit 1

} finally {
	Stop-Transcript
}
