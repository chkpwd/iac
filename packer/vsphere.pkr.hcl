/*
SSH Communicator uses powershell to execute scripts : https://github.com/hashicorp/packer/issues/6664
execute_command = "{{.Path}}; exit $LastExitCode"
*/

locals {
  build_version = formatdate("YY.MM", timestamp())
  build_date = formatdate("YYYY-MM-DD hh:mm ZZZ", timestamp())
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
  notes                 = "Version: ${ local.build_version }\nBuild Date: ${ local.build_date }\nISO: ${ var.os_iso_url }"

  # VM Settings
  vm_name       = var.machine_name
  guest_os_type = var.guest_os_type

  ssh_username = var.connection_username
  ssh_password = var.connection_password

  firmware     = "efi"

  cdrom_type   = var.cdrom_controller_type
  disk_controller_type =  var.vhd_controller_type

  CPUs            = var.num_cores
  RAM             = var.mem_size
  CPU_hot_plug    = true
  RAM_hot_plug    = true
  RAM_reserve_all = true

  storage {
    disk_size             = var.root_disk_size
    disk_thin_provisioned = true
  }

  iso_checksum = "${var.iso_checksum_type}:${var.iso_checksum}"
  iso_url      = var.os_iso_url

  network_adapters {
    network      = var.network_name
    network_card = var.nic_type
  }

  http_ip       = var.listen_address

  http_port_min = 8687
  http_port_max = 8687

  http_content  = var.preseed != "" ? {
    "/preseed.cfg" = templatefile("${abspath(path.root)}/files/${var.preseed}.pkrtpl.hcl", {
      user_fullname = var.connection_username,
      user_name     = var.connection_username,
      user_password = var.connection_password
    })
  } : {}

  boot_command = [
    "c<wait>",
    "linux /install.amd/vmlinuz <wait>",
    "auto url=http://{{ .HTTPIP }}:{{ .HTTPPort }}/preseed.cfg <wait>",
    "priority=high <wait>",
    "locale=en_US.UTF-8 <wait>",
    "keymap=us <wait>",
    "hostname=${var.hostname} <wait>",
    "domain=${var.domain} <wait>",
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
  notes               = "Version: ${ local.build_version }\nBuild Date: ${ local.build_date }\nISO: ${ var.os_iso_url }"

  # VM Settings
  vm_name     		      = var.machine_name
  ip_wait_timeout       = "45m"
  shutdown_command      = "shutdown /s /t 10 /f /d p:4:1 /c 'Packer Shutdown'"
  shutdown_timeout      = "15m"
  vm_version            = var.vm_hardware_version
  iso_paths             = [
    var.os_iso_path,
    "[] /usr/lib/vmware/isoimages/windows.iso"
  ]
  iso_checksum          = var.iso_checksum
  guest_os_type         = var.guest_os_type

  firmware              = "efi"

  disk_controller_type  = var.vhd_controller_type
  cdrom_type   = var.cdrom_controller_type

  CPUs                  = var.num_cores
  cpu_cores             = var.num_cores
  CPU_hot_plug          = true
  RAM                   = var.mem_size
  RAM_hot_plug          = true

  # SSH Communicator Settings
  communicator              = "ssh"
  ssh_username              = var.connection_username
  ssh_password              = var.connection_password
  ssh_private_key_file      = "~/.ssh/main"
  ssh_timeout               = "1h"
  ssh_clear_authorized_keys = true

  storage {
    disk_size             = var.root_disk_size
    disk_thin_provisioned = true
  }

  network_adapters {
    # For windows, the vmware tools network drivers are required to be connected by floppy before tools is installed
    network      = var.network_name
    network_card = var.nic_type
  }

  floppy_files          = [
    "./boot_config/${var.os_version}/Autounattend.xml",
    "./scripts/Setup-OpenSSH.ps1",
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
    inventory_file_template = "{{ .HostAlias }} ansible_host={{ .Host }} ansible_user={{ .User }} ansible_password={{ .Password }} ansible_become_password={{ .Password }} ansible_ssh_common_args='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PubkeyAuthentication=no'"
    ansible_env_vars        = [
      "ANSIBLE_INVENTORY_ENABLED=ini",
      "ANSIBLE_CONFIG=../ansible/ansible.cfg",
      "ANSIBLE_HOST_KEY_CHECKING=false",
      "ANSIBLE_VERBOSITY=2"
    ]
  }
}

build {
  sources = [
    "source.vsphere-iso.windows"
  ]
  provisioner "powershell" {
    execute_command = "{{.Path}}; exit $LastExitCode"
    elevated_user = var.connection_username
    elevated_password = var.connection_password
    scripts = [
      "scripts/Modify-UAC.ps1",
      "scripts/Enable-Other-Updates.ps1",
      "scripts/Install-Chocolatey.ps1",
      "scripts/Build.ps1",
      "scripts/Setup-NewUser.ps1",
      // "scripts/Remove-UpdateCache.ps1", # This fails on Windows 11
      "scripts/Invoke-Defrag.ps1",
      "scripts/Reset-EmptySpace.ps1",
      "scripts/Modify-UAC.ps1"
    ]
  }
}
