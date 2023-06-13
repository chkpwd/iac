# Create new user
$username = "hyoga"   
$password = ConvertTo-SecureString "DefaultPass@" -AsPlainText -Force
$logFile = "C:\Automation\Packer\new_user.log"

Function Write-Log {
param(
	[Parameter(Mandatory = $true)][string] $message,
	[Parameter(Mandatory = $false)]
	[ValidateSet("INFO","WARN","ERROR")]
	[string] $level = "INFO"
)

# Create timestamp
$timestamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")

# Append content to log file
Add-Content -Path $logFile -Value "$timestamp [$level] - $message"
}

Function New-LocalAdmin {
	process {
	try {
		New-LocalUser "$username" -Password $password -FullName "$username" -Description "local admin" -ErrorAction stop
		Write-Log -message "$username local user crated"
		# Add new user to administrator group
		Add-LocalGroupMember -Group "Administrators" -Member "$username" -ErrorAction stop
		Write-Log -message "$username added to the local administrator group"
	}catch{
		Write-log -message "Creating local account failed" -level "ERROR"
	}
	}    
}

Write-Log -message "#########"
Write-Log -message "$env:COMPUTERNAME - Create local admin account"
New-LocalAdmin
Write-Log -message "#########"