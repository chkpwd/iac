#Requires -version 5
#Requires -RunAsAdministrator

# Enable tls1.2 from default (SSL3, TLS)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3 -bor [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

# Enable TLS1.2 permanently
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord -Force
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319' -Name 'SchUseStrongCrypto' -Value '1' -Type DWord -Force 

# Install Nuget
Install-PackageProvider -Name NuGet -Force
Set-PSRepository -InstallationPolicy Trusted -Name PSGallery 

# Enable OpenSSH for Windows
[bool]$isSSHClientInstalled = Get-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0 | Where-Object { $_.State -eq 'Installed' } | Measure-Object | Select-Object -ExpandProperty Count
[bool]$isSSHServerInstalled = Get-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Where-Object { $_.State -eq 'Installed' } | Measure-Object | Select-Object -ExpandProperty Count
if (-not($isSSHClientInstalled)) {
    Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0
}
if (-not($isSSHServerInstalled)) {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

    if (Get-Service sshd -ErrorAction SilentlyContinue) {
        New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force
        Set-Service -Name sshd -StartupType 'Automatic'
        Start-Service sshd
        Set-Service -Name ssh-agent -StartupType 'Automatic'
        Start-Service ssh-agent
    }
}


# Create SSH publickey lists and adjust file permission(s)
$ssh_admin_authorized_filepath = 'C:\ProgramData\ssh\administrators_authorized_keys'
$ssh_admin_pubkey_list = "

# OpenSSH compatible public-key lists

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBK2VnKgOX7i1ISETheqjAO3/xo6D9n7QbWyfDAPsXwa

".Split("`r`n") -notmatch '^#.*' | Where-Object { $_.trim() }
$ssh_admin_pubkey_list | Out-File -Encoding ascii -FilePath $ssh_admin_authorized_filepath -Force

if (Test-Path $ssh_admin_authorized_filepath)
{
    # Fix owner and permissions
    # https://github.com/PowerShell/Win32-OpenSSH/wiki/Security-protection-of-various-files-in-Win32-OpenSSH
    Set-Location C:\ProgramData\ssh
    takeown /F administrators_authorized_keys /A
    icacls administrators_authorized_keys /inheritance:r
    icacls administrators_authorized_keys /grant SYSTEM:`(F`)
    icacls administrators_authorized_keys /grant BUILTIN\Administrators:`(F`)
}


# Enable PSRemoting over SSH
$sshd_config_filepath = 'C:\ProgramData\ssh\sshd_config'
if ((Test-Path $sshd_config_filepath) -And (Test-Path 'C:\Program Files\PowerShell\7')) {
    New-Item -ItemType SymbolicLink -Path C:\pwsh -Target 'C:\Program Files\PowerShell\7'
    $sshd_config = Get-Content -Path $sshd_config_filepath
    $sshd_config -replace "^Subsystem.*", "Subsystem sftp sftp-server.exe`nSubsystem powershell c:/pwsh/pwsh.exe -sshs -NoLogo" `
    | Set-Content -Path $sshd_config_filepath -Force
    Restart-Service sshd
}