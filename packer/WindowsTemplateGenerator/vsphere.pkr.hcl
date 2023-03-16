source "vsphere-iso" "windows" {
  # vCenter settings
  vcenter_server      = var.vcenter_server
  username            = var.vcenter_username
  password            = var.vcenter_password
  insecure_connection = true #TODO: Add ca to docker
  cluster             = var.vcenter_cluster
  datacenter          = var.vcenter_datacenter
  host                = var.vcenter_host
  datastore           = var.vcenter_datastore
  convert_to_template = true
  folder              = var.vcenter_folder
  boot_command        = var.boot_command
  boot_wait           = "3s"

  # VM Settings
  ip_wait_timeout       = "45m"
  communicator          = "winrm"
  winrm_username        = var.connection_username
  winrm_password        = var.connection_password
  winrm_timeout         = "12h"
  winrm_port            = "5985"
  shutdown_command      = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer Shutdown\""
  shutdown_timeout      = "15m"
  vm_version            = var.vm_hardware_version
  iso_paths              = [
      var.os_iso_path
  ]

  iso_checksum          = var.iso_checksum
  vm_name               = "Windows${ var.os_version }"
  guest_os_type         = var.guest_os_type
  disk_controller_type  = ["pvscsi"] # Windows requires vmware tools drivers for pvscsi to work
  network_adapters {
    # For windows, the vmware tools network drivers are required to be connected by floppy before tools is installed
    network = var.vm_network
    network_card = var.nic_type
  }
  storage {
    disk_size = var.root_disk_size
    disk_thin_provisioned = true
  }
  CPUs                  = var.num_cpu
  cpu_cores             = var.num_cores
  CPU_hot_plug          = true
  RAM                   = var.vm_ram
  RAM_hot_plug          = true
  firmware              = "efi"
  floppy_files          = [
      "./boot_config/${var.os_version}/Autounattend.xml",
      "./scripts/winrm.bat",
      "./scripts/Install-VMWareTools.ps1",
      "./files/TaskbarLayout.xml",
      "./drivers/"
  ]
}

build {
    # Windows builds
    sources = [
        "source.vsphere-iso.windows",
    ]
    provisioner "powershell" {
        elevated_user = var.connection_username
        elevated_password = var.connection_password
        scripts = [
            "scripts/Disable-UAC.ps1", # I re-enable UAC with ansible post deployment
            "scripts/Enable-Other-Updates.ps1", 
            "scripts/Install-Chocolatey.ps1",
            "scripts/Install-OpenSSH.ps1",
            "scripts/Build.ps1",
            "scripts/Setup-NewUser.ps1"
        ]
    }
    provisioner "windows-update" { # This requires windows-update-provisioner https://github.com/rgl/packer-provisioner-windows-update
        pause_before = "30s"
        filters = [
            "exclude:$_.Title -like '*VMware*'",
            "exclude:$_.Title -like '*Preview*'",
            "include:$true"
        ]
    }
    provisioner "powershell" {
        elevated_user = var.connection_username
        elevated_password = var.connection_password
        scripts = [
            "scripts/Compile-DotNet-Assemblies.ps1",
            "scripts/Remove-UpdateCache.ps1",
            "scripts/Invoke-Defrag.ps1",
            "scripts/Reset-EmptySpace.ps1"
        ]
    }
}

packer {
  required_plugins {
    windows-update = {
      version = "0.14.1"
      source = "github.com/rgl/windows-update"
    }
  }
}
