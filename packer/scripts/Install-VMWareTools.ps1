<#
.FUNCTIONALITY
This is a VMWare tools install script that re-attempts the install if it finds that the VMWARE tools service has failed to install on the first attempt 1

.SYNOPSIS
- This script can be used as part of automating windows 10/2019 builds via autounattend.xml with packer.io based builds
- The Packer instance requires the VMWare tools service to be running at the end of the build, else, it will fail
- Due to an issue Windows "VMware tools service" failing to install on the first attempt, the code in this script compltes a re-install of the VMWARE tools package
- The below code is mostly based on the script within the following blog post:
- https://scriptech.io/automatically-reinstalling-vmware-tools-on-server2016-after-the-first-attempt-fails-to-install-the-vmtools-service/

.NOTES
Change log

July 24, 2020
- Initial version

Nov 28, 2021
- Added Write-CustomLog function

Nov 30, 2021
- Updated code to ID correct log name
- Added Show-Status function

Feb 13, 2022
- Logging changed to new file, rather than adding to existing WinPackerBuild-date.txt file

Nov 30, 2023
- stylistic changes
- Updated shoutouts

.DESCRIPTION
Author oreynolds@gmail.com and Tim from the scriptech.io blog
https://scriptech.io/automatically-reinstalling-vmware-tools-on-server2016-after-the-first-attempt-fails-to-install-the-vmtools-service/

.EXAMPLE
./Install-VMTools.ps1

.NOTES

.Link
https://scriptech.io/automatically-reinstalling-vmware-tools-on-server2016-after-the-first-attempt-fails-to-install-the-vmtools-service/
https://github.com/getvpro/Build-Packer
https://github.com/getvpro/Build-Packer/blob/master/Scripts/Install-VMTools.ps1
https://github.com/tigattack

#>

function Get-VMToolsInstalled {
    $path32bit = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall"
    $path64bit = "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    $vmwareToolsPattern = "*VMware Tools*"

    if ((Get-ChildItem $path32bit | Where-Object { $_.GetValue("DisplayName") -like $vmwareToolsPattern }).Length -gt 0) {
        return "32"
    }

    if ((Get-ChildItem $path64bit | Where-Object { $_.GetValue("DisplayName") -like $vmwareToolsPattern }).Length -gt 0) {
        return "64"
    }

    return $null
}

function Install-VMwareTools {
    Start-Process "setup64.exe" -ArgumentList '/s /v "/qb REBOOT=R"' -Wait
}

function Check-VMwareService {
    $iRepeat = 0

    while ($iRepeat -lt 5) {
        Start-Sleep -Seconds 2
        $status = (Get-Service "VMTools" -ErrorAction SilentlyContinue).Status

        if ($status -eq "Running") {
            Write-Output "`nVMware Tools service is running."
            return $true
        } else {
            Write-Output "`nVMware Tools service is not running."
            $iRepeat++
        }
    }

    return $false
}

function Uninstall-VMwareTools {
    $GUID = Get-VMToolsInstalled
    if ($GUID) {
        Start-Process -FilePath msiexec.exe -ArgumentList "/X $GUID /quiet /norestart" -Wait
    }
}

# Script begins here
$scriptLog = "C:\Automation\Packer\Install-VMTools.log"
Start-Transcript $scriptLog -Force

if (-not (Test-Path C:\Automation\Packer)) {
    New-Item -Path C:\Automation\Packer -ItemType Directory | Out-Null
}

Set-Location E:\

Write-Output "`nInitiating VMware Tools installation (attempt no. 1)"
Install-VMwareTools

if (-not (Check-VMwareService)) {
    Write-Output "`nRe-attempting installation after failed first attempt"
    Uninstall-VMwareTools
    Install-VMwareTools

    if (-not (Check-VMwareService)) {
        Write-Output "VMWare Tools installation failed. Exiting."
        Stop-Transcript
        Exit 1
    }
}

Stop-Transcript
