$netProfile = Get-NetConnectionProfile
Set-NetConnectionProfile -Name $netProfile.Name -NetworkCategory Private