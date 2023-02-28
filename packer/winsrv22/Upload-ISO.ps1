[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)]
  [String]$IsoPath,
  [String]$Datastore = 'vsphere_nfs',
  [Parameter(Mandatory=$true)]
	[string]$Username,
  [Parameter(Mandatory=$true)]
	[SecureString]$Password
)

$iso_store_path = 'template\iso'

$ErrorActionPreference = 'Stop'

# Check for PowerCLI module
If (Get-Module -ListAvailable -Name VMware.VimAutomation.Core) {
    Import-Module VMware.VimAutomation.Core -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
}
# Install if not exist
Else {
	Write-Output "'VMware.VimAutomation.Core' module is not installed. Installing..."
	# Get installation policy for PSRepository 'PSGallery'
	$psGalleryPolicy = (Get-PSRepository -Name PSGallery).InstallationPolicy
	# Set to trusted if not
	If ($psGalleryPolicy -ne 'Trusted') {
		Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted
	}
	# Install PowerCLI module
	Install-Module VMware.PowerCLI -Force 2>&1>$null 3>$null
	# Return PSGallery repo to original installation policy
	If ($psGalleryPolicy -ne 'Trusted') {
		Set-PSRepository -Name 'PSGallery' -InstallationPolicy $psGalleryPolicy
	}

	Import-Module VMware.VimAutomation.Core -Force -ErrorAction SilentlyContinue -WarningAction SilentlyContinue | Out-Null
}

# Set configuration
Set-PowerCLIConfiguration -Scope User -ParticipateInCEIP $false -Confirm:$false | Out-Null
Set-PowerCLIConfiguration -Scope User -InvalidCertificateAction Ignore -Confirm:$false | Out-Null

# Build credentials
[PSCredential]$vcCredential = New-Object System.Management.Automation.PSCredential($Username,$Password)

# Create VIServer connection
Try {
    Connect-VIServer -Server 'ronin.typhon.tech' -Credential $vcCredential | Out-Null
    Write-Output 'Connected to VIServer.'
}
Catch {
    Write-Warning 'Failed to connect to VIServer.'
    throw $_
}

# ISO path sutff
If (-not (Test-Path $IsoPath)) {
    throw 'ISO path cannot be accessed or does not exist.'
}
$IsoName = Split-Path -Path $IsoPath -Leaf
try {
  try {
    # https://kb.vmware.com/s/article/2001041

    # Get ds
    Write-Output 'Getting datastore'
    $ds = Get-Datastore $Datastore

    # Create PSDrive mapped to datastore
    Write-Output 'Creating PSDrive'
    New-PSDrive -Location $ds -Name vCDS -PSProvider VimDatastore -Root "\" | Out-Null
  }
  Catch {
    Write-Warning 'Failed to map datastore.'
    throw $_
  }

  try {
    # Check ISO doesn't exist
    If (-not (Get-ChildItem -Path vCDS:\$iso_store_path\$IsoName -ErrorAction SilentlyContinue)) {
      # Copy ISO to datastore
      Write-Output 'Copying ISO'
      Copy-DatastoreItem -Item $IsoPath -Destination vCDS:\$iso_store_path
    }
    else {
      Write-Output 'ISO already exists; not copying.'
    }
  }
  Catch {
    Write-Warning 'Failed to copy ISO to datastore.'
    throw $_
  }

  try {
    # Find old ISOs
    Write-Output 'Checking for old ISOs...'
    $oldIsos = Get-ChildItem -Path vCDS:\$iso_store_path -Filter *.iso -Recurse | Where-Object { 
      $_.Name -match "^en-us_windows_server_2022.*\.iso$" -and
      $_.Name -ne $IsoName
    } 

    # Remove old ISOs if any are found
    if ($oldIsos.Count -gt 0) {

      foreach ($iso in $oldIsos) {
        # Delete old ISO
        $oldIsoName = Split-Path -Path $iso -Leaf
        Write-Output "Removing $oldIsoName"
        Remove-Item -Path "vCDS:\$iso_store_path\$oldIsoName" -Force
      }
    }
    else {
      Write-Output 'No old ISOs found.'
    }
  }
  Catch {
    Write-Warning 'Failed to find/remove old ISO(s).'
    throw $_
  }

  try {
    # Patch Packer vars
    Write-Output 'Patching Packer vars'
    Set-Content -Path .\vars.auto.pkrvars.hcl -Value ((Get-Content .\vars.auto.pkrvars.hcl) -replace "en-us_windows_server_2022.*\.iso", $IsoName)
  }
  Catch {
    Write-Warning 'Failed to patch Packer vars.'
    throw $_
  }

  # Commit changes
  Set-Location -Path $PSScriptRoot

  git add vars.auto.pkrvars.hcl
  git commit -m 'feat(pkr-win): update ISO path'

  Set-Location -Path -
}
catch {
  throw $_
}
finally {
  # Remove PSDrive
  Write-Output 'Removing PSDrive'
  Remove-PSDrive -Name vCDS

  # Disconnect from VIServer
  Write-Output 'Disconnecting from VIServer'
  Disconnect-VIServer -Confirm:$false | Out-Null
}
