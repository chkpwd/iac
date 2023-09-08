locals {
  preseed_config = {
    "/preseed.cfg" = templatefile("${abspath(path.root)}/files/${var.preseed}.pkrtpl.hcl", {
      user_fullname = var.connection_username,
      user_name     = var.connection_username,
      user_password = var.connection_password
    })
  }
}

source "vsphere-iso" "linux" {
  vcenter_server        = var.vcenter_server
  datacenter            = var.vcenter_datacenter
  username              = var.vcenter_username
  password              = var.vcenter_password
  datastore             = var.vcenter_datastore
  cluster               = var.vcenter_cluster
  insecure_connection   = true
  convert_to_template   = true
  folder                = var.vcenter_folder

  # VM Settings
  vm_name       = var.machine_name
  guest_os_type = var.guest_os_type

  ssh_username = var.connection_username
  ssh_password = var.connection_password
  http_content = local.preseed_config

  firmware     = "efi"

  CPUs            = var.num_cores
  RAM             = var.mem_size
  CPU_hot_plug    = true
  RAM_hot_plug    = true
  RAM_reserve_all = true

  disk_controller_type =  ["lsilogic-sas"]

  storage {
    disk_size             = var.root_disk_size
    disk_thin_provisioned = true
  }

  iso_checksum = "${var.iso_checksum_type}:${var.iso_checksum}"
  iso_url      = var.os_iso_url

  network_adapters {
    network      =  var.network_name
    network_card = var.nic_type
  }

  boot_command = [
    "c<wait>",
    "linux /install.amd/vmlinuz ",
    "auto url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg ",
    "priority=high ",
    "locale=en_US.UTF-8 ",
    "keymap=us ",
    "hostname=${var.hostname} ",
    "domain=${var.domain} ",
    "---<enter>",
    "initrd /install.amd/initrd.gz<enter>",
    "boot<enter>"
  ]
}

source "vsphere-iso" "windows" {
  vcenter_server      = var.vcenter_server
  datacenter          = var.vcenter_datacenter
  username            = var.vcenter_username
  password            = var.vcenter_password
  datastore           = var.vcenter_datastore
  cluster             = var.vcenter_cluster
  insecure_connection = true
  convert_to_template = true
  folder              = var.vcenter_folder
  boot_command        = var.boot_command
  boot_wait           = "3s"

  # VM Settings
  vm_name     		    = var.machine_name
  ip_wait_timeout       = "45m"
  communicator          = "winrm"
  winrm_username        = var.connection_username
  winrm_password        = var.connection_password
  winrm_timeout         = "12h"
  winrm_port            = "5985"
  shutdown_command      = "shutdown /s /t 10 /f /d p:4:1 /c \"Packer Shutdown\""
  shutdown_timeout      = "15m"
  vm_version            = var.vm_hardware_version
  iso_paths             = [var.os_iso_path]
  iso_checksum          = var.iso_checksum
  guest_os_type         = var.guest_os_type
  disk_controller_type  = ["lsilogic-sas"]

  network_adapters {
    # For windows, the vmware tools network drivers are required to be connected by floppy before tools is installed
    network      = var.network_name
    network_card = var.nic_type
  }

  storage {
    disk_size             = var.root_disk_size
    disk_thin_provisioned = true
  }

  CPUs                  = var.num_cores
  cpu_cores             = var.num_cores
  CPU_hot_plug          = true
  RAM                   = var.mem_size
  RAM_hot_plug          = true
  firmware              = "efi"
  floppy_files          = [
    "./boot_config/${var.os_version}/Autounattend.xml",
    "./scripts/winrm.bat",
    "./scripts/Install-VMWareTools.ps1",
    "./scripts/Fix-Firewall.ps1",
    "./files/TaskbarLayout.xml",
  ]
}

build {
  sources = [
    "source.vsphere-iso.linux"
  ]

  provisioner "ansible" {
    playbook_file           = "../ansible/playbooks/packer.yaml"
    use_proxy               = false
    max_retries             = 3
    inventory_file_template = "{{ .HostAlias }} ansible_host={{ .Host }} ansible_user={{ .User }} ansible_password={{ .Password }} ansible_become_password={{ .Password }}"
    ansible_env_vars        = [
      "ANSIBLE_CONFIG=../ansible/ansible.cfg", 
      "ANSIBLE_HOST_KEY_CHECKING=False",
      "ANSIBLE_VERBOSITY=2"
    ]
  }

}

build {
    sources = [
      "source.vsphere-iso.windows"
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
