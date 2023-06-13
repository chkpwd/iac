$VerbosePreference = "Continue"

#$wmi_operatingsystem = Get-WmiObject -Class win32_operatingsystem
# Checks if using Server 2008
#if([int]$wmi_operatingsystem.version.Substring(0,1) -le 6) { # Server 2008
#    Write-Verbose "Using 10.2.5 tools for 2008R2 (this is for compatability issues with later tools versions that breaks guest customization."
#    $url = 'https://packages.vmware.com/tools/releases/10.2.5/windows/x64/VMware-tools-10.2.5-8068406-x86_64.exe'
#} else { # Anything above 2008
#    Write-Verbose "Latest Tools selected (not 2008R2)"

    $content = Invoke-WebRequest -UseBasicParsing -Uri "https://packages.vmware.com/tools/releases/latest/windows/x64/"
    $version = ($content.Links | Where-Object {$_.href -like "VMware-tools*" }).href

    $url = "https://packages.vmware.com/tools/releases/latest/windows/x64/$($version)"
#}

# install vmware tools
$file = 'tools.exe'
$path = "C:\Windows\Temp\$file"
$timeout = 30 # Timeout in minutes for it to fail this job
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url,$path)
$args = '/s /v /qn reboot=r'
Write-Verbose "Tools download successful. Install starting."
$timer = [Diagnostics.Stopwatch]::StartNew()
Start-Process -FilePath $path -ArgumentList $args -PassThru

function Test-VMInstall {
    $RegKey = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\')

    foreach ($key in $RegKey) {
        if ((Get-ItemProperty -Path $key.PSPath).DisplayName -match "vmware") {
            return $true
        }
    }
    return $false
}

$toolswait = $true

While ($toolswait){
    if(!(Test-VMInstall)){
        if($timer.Elaspsed.TotalMinutes -gt $timeout) {
            Write-Verbose "Tools not detected within timeout. Failing job."
            Exit 1
        }
        Write-Verbose "Tools not detected yet."
        Write-Verbose "Time left until timeout: $([math]::Round($timeout - $timer.Elapsed.TotalMinutes)) minutes."
        Write-Verbose "Sleeping 10 seconds before checking again."
        Start-Sleep -Seconds 10
    } else {
        $toolswait = $false
    }
}

Write-Verbose "VMTools detected, sleeping 200 seconds for installer cleanup."
Start-Sleep -Seconds 200
