resource "random_password" "main" {
  length           = 16
  override_special = "_%@"
  special          = true
}

resource "proxmox_virtual_environment_vm" "main" {
  tags        = var.machine.tags
  name        = var.machine.name

  started = var.machine.started
  on_boot = var.machine.on_boot

  agent {
    enabled = var.machine.enable_agent
  }

  node_name = var.node
  bios = var.machine.bios

  cpu {
    cores = var.spec.cpu.cores
    architecture = var.spec.cpu.architecture
    flags = var.spec.cpu.flags
    hotplugged = var.spec.cpu.hotplugged
    type = var.spec.cpu.type
  }

  scsi_hardware = var.spec.scsi_hardware

  disk {
    cache        = var.spec.disk.cache
    datastore_id = var.spec.disk.datastore_id
    interface    = var.spec.disk.interface
  }

  network_device {
    bridge = var.spec.network.bridge
  }

  dynamic "initialization" {
    for_each = null != var.spec.initialization ? var.spec.initialization : {}

    content {
      ip_config {
        ipv4 {
          address = var.spec.initialization.ip_config.ipv4.address
          gateway = var.spec.initialization.ip_config.ipv4.gateway
        }
      }
      user_account {
        keys     = var.spec.initialization.user_account.keys
        password = var.spec.initialization.user_account.password
        username = var.spec.initialization.user_account.username
      }
      user_data_file_id = null != var.spec.initialization.user_account ? {} : var.initialization.user_data_file_id 
    }
  }

  dynamic "tpm_state" {
    for_each = null != var.machine.tpm ? var.machine.tpm : {}

    content {
      version = var.machine.tpm.version
      datastore_id = var.machine.tpm.datastore_id
    }
  }
}
