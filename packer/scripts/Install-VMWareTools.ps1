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

    if (((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") | Where-Object { $_.GetValue( "DisplayName" ) -like "*VMware Tools*" } ).Length -gt 0) {
        [int]$Version = "32"
    }

    if (((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") | Where-Object { $_.GetValue( "DisplayName" ) -like "*VMware Tools*" } ).Length -gt 0) {
        [int]$Version = "64"
    }

    return $Version
}

function Show-Status {
    Write-Output "VMware tools is installed."
    Start-Sleep -Seconds 5
}

if (-not (Test-Path C:\Automation\Packer)) {
    New-Item -Path C:\Automation\Packer -ItemType Directory | Out-Null
}
$ScriptLog = "C:\Automation\Packer\Install-VMTools.log"

Start-Transcript $ScriptLog -Force

### 1 - Set the current working directory to whichever drive corresponds to the mounted VMWare Tools installation ISO

Set-Location E:\

### 2 - Install attempt #1
Write-Output "`nInitiating VMware Tools installation (attempt no. 1)"

Start-Process "setup64.exe" -ArgumentList '/s /v "/qb REBOOT=R"' -Wait

### 3 - After the installation is finished, check to see if the 'VMTools' service enters the 'Running' state every 2 seconds for 10 seconds
$Running = $false
$iRepeat = 0

while (-not $Running -and $iRepeat -lt 5) {
    Write-Output "`nPausing for 2 seconds before checking state of VMware tools service..."

    Start-Sleep -Seconds 2

    $status = (Get-Service "VMTools" -ErrorAction SilentlyContinue).Status

    if ($status -notlike "Running") {
        Write-Output "`nVMware Tools service is not running."
        $iRepeat++
    }
    else {
        Write-Output "`nVMware Tools service is running after first attempt."
        $Running = $true
    }
}

### 4 - if the service never enters the 'Running' state, re-install VMWare Tools
if (-not $Running) {

    # Uninstall VMWare Tools
    Write-Output "`nUninstalling VMware Tools after first attempt failed..."

    if (Get-VMToolsInstalled -eq "32") {
        $GUID = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -Like '*VMWARE Tools*' }).PSChildName
    } else {
        $GUID = (Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -Like '*VMWARE Tools*' }).PSChildName
    }

    ### 5 - Un-install VMWARe tools based on 32-bit/64-bit install GUIDs captured via Get-VMToolsIsInstalled function

    Start-Process -FilePath msiexec.exe -ArgumentList "/X $GUID /quiet /norestart" -Wait

    Write-Output "`nInitiating VMware Tools installation (attempt no. 2)"

    #Install VMWare Tools
    Start-Process "setup64.exe" -ArgumentList '/s /v "/qb REBOOT=R"' -Wait

    ### 6 - Re-check again if VMTools service has been installed and is started

    $iRepeat = 0
    while (-not $Running -and $iRepeat -lt 5) {

        Write-Output "`nPausing for 2 seconds before checking state of VMware tools service..."

        Start-Sleep -Seconds 2

        $status = (Get-Service "VMTools" -ErrorAction SilentlyContinue).Status

        if ($status -notlike "Running") {
        Write-Output "`nVMware Tools service is not running."
        $iRepeat++
        }
        else {
        Write-Output "`nVMware Tools service is running after second attempt."
        $Running = $true
        }

    }

    ### 7 if after the reinstall, the service is still not running, this is a failed deployment

    if (-not $Running) {
        Write-Output "VMWare Tools is still NOT installed correctly `n
        This window will remain open for 5 minutes, then exit."

        Stop-Transcript
        Start-Sleep -Seconds 300
        EXIT 1

    }

}

Stop-Transcript
