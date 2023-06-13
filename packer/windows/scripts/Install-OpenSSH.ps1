try {
  $logDir = "$env:temp\Packer"
  If (-not (Test-Path $logDir)) {
    Write-Output "`nCreating log directory ($logDir).`n"
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
  }

  Start-Transcript "$logDir\Install-OpenSSH.log" -Force

  $ErrorActionPreference = 'Stop'

  # Define paths
  $temp = [Environment]::GetEnvironmentVariable("TEMP", [EnvironmentVariableTarget]::Machine)
  $installDestination = 'C:\Program Files\OpenSSH'
  $configPath = 'C:\ProgramData\ssh'
  $ssh_repo_url = 'https://github.com/PowerShell/Win32-OpenSSH/releases/latest/'

  # Generate random password
  Add-Type -AssemblyName System.Web
  $password = [System.Web.Security.Membership]::GeneratePassword(64,20)

  ## Set network connection protocol to TLS 1.2
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

  # Install Openssh
  Write-Output "`Downloading OpenSSH"

  ## Create a web request to retrieve the latest release download link
  # https://github.com/PowerShell/Win32-OpenSSH/wiki/How-to-retrieve-links-to-latest-packages
  $request = [System.Net.WebRequest]::Create($ssh_repo_url)
  $request.AllowAutoRedirect=$false
  $response=$request.GetResponse()
  $source = $([String]$response.GetResponseHeader("Location")).Replace('tag','download') + '/OpenSSH-Win64.zip'

  # Download the latest OpenSSH for Windows package to the current working directory
  Invoke-WebRequest -Uri "$source" -OutFile "$temp\OpenSSH-Win64.zip" -UseBasicParsing

  Write-Output "`nExtracting OpenSSH"

  # Extract the ZIP to a temporary location
  Expand-Archive -Path "$temp\OpenSSH-Win64.zip" -DestinationPath $temp -Force

  # Move the extracted ZIP contents from the temporary location to C:\Program Files\OpenSSH\
  Move-Item "$temp\OpenSSH-Win64" -Destination $installDestination -Force

  # Unblock the files in C:\Program Files\OpenSSH\
  Get-ChildItem -Path $installDestination | Unblock-File

  # Fix event log error on install
  # https://github.com/PowerShell/Win32-OpenSSH/issues/1635
  $acl = Get-Acl 'C:\Program Files\OpenSSH\'
  $p = New-Object System.Security.Principal.NTAccount("NT Service\EventLog")
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($p, "Read", "ContainerInherit, ObjectInherit", "None", "Allow")
  $acl.AddAccessRule($accessRule)
  $acl | Set-Acl -Path 'C:\Program Files\OpenSSH\'

  # Run OpenSSH install script
  Write-Output "`nInstalling OpenSSH:`n"
  & "$installDestination\install-sshd.ps1"

  Stop-Service sshd -Force

  # Set PowerShell as default shell
  Write-Output "`nSetting PowerShell as OpenSSH's default shell"

  $regkeys = @{
    'DefaultShell' = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    'DefaultShellCommandOption' = '/c'
  }
  foreach ($key in $regkeys.GetEnumerator()) {
    New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name $key.Name -Value $key.Value -PropertyType String -Force | Out-Null
  }

  # Start sshd and set autostart
  Write-Output "`nSet sshd to autostart"
  Get-Service sshd | Set-Service -Status Running -StartupType Automatic | Out-Null

	# Configure firewall rule
	If (-not (Get-NetFirewallRule -Name sshd -ErrorAction SilentlyContinue)) {
		Write-Output "`nConfiguring firewall"
		New-NetFirewallRule -Name sshd -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null
	}

}
catch {
	Write-Output "Error: $($_.Exception.Message)"
	Write-Output "`nExiting in 90 seconds...`n"

	Start-Sleep -Seconds 90
}
finally {
	Stop-Transcript
}
