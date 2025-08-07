locals {
  packer_timestamp = formatdate("YYYYMMDD-hhmm", timestamp())
}

source "proxmox-iso" "windows" {
  vm_name      = var.machine_name
  communicator = "winrm"

  boot_iso {
    iso_file = var.os_iso_path
    # iso_checksum = var.iso_checksum
    unmount  = true
  }

  additional_iso_files {
    unmount          = true
    type             = "sata"
    iso_storage_pool = "local"
    cd_files = [
      "./files/drivers/*",
      "./boot_config/${var.os_version}/Autounattend.xml",
      "./scripts/Setup-OpenSSH.ps1",
      "./scripts/Fix-Firewall.ps1",
      "./files/TaskbarLayout.xml",
    ]
  }

  additional_iso_files {
    unmount          = true
    type             = "sata"
    iso_storage_pool = "proxmox-iso"
    iso_file         = var.virtio_iso_file
  }

  boot_command = var.boot_command
  boot_wait    = "3s"
  bios         = var.bios

  disks {
    cache_mode   = "none"
    disk_size    = "40G"
    type         = "virtio"
    format       = "raw"
    storage_pool = "prod-nvme"
  }

  efi_config {
    efi_storage_pool  = "prod-nvme"
    efi_type          = "4m"
    pre_enrolled_keys = true
  }

  cores              = "2"
  memory             = "4096"
  ballooning_minimum = var.ballooning_minimum
  sockets            = var.sockets
  os                 = var.os_family
  disable_kvm        = var.disable_kvm
  cpu_type           = "host"

  network_adapters {
    bridge      = var.network_adapters.bridge
    model       = var.network_adapters.model
    firewall    = var.network_adapters.firewall
    mac_address = var.network_adapters.mac_address
    vlan_tag    = var.network_adapters.vlan_tag != "" && var.network_adapters.vlan_tag != "0" ? var.network_adapters.vlan_tag : null
  }

  machine                  = var.machine
  node                     = var.proxmox_node
  template_name            = "windows-srv-${var.os_version}.${local.packer_timestamp}"
  insecure_skip_tls_verify = var.insecure_skip_tls_verify
  scsi_controller          = "virtio-scsi-single"
  winrm_password           = var.winrm_password
  winrm_timeout            = "8h"
  winrm_username           = var.winrm_username
  tags                     = var.tags
  task_timeout             = var.task_timeout
  qemu_agent               = var.qemu_agent

  vga {
    type   = var.vga.type
    memory = var.vga.memory
  }
}

build {
  sources = ["source.proxmox-iso.windows"]

  provisioner "powershell" {
    elevated_password = var.winrm_password
    elevated_user     = var.winrm_username
    scripts = [
      "scripts/Enable-Other-Updates.ps1",
      "scripts/Install-Chocolatey.ps1",
      "scripts/Build.ps1",
      "scripts/Setup-NewUser.ps1",
      "scripts/Remove-UpdateCache.ps1",
      "scripts/Invoke-Defrag.ps1",
      "scripts/Reset-EmptySpace.ps1",
      "scripts/Modify-UAC.ps1"
    ]
  }
}
