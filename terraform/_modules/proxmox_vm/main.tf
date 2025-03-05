resource "random_password" "main" {
  length           = 16
  override_special = "_%@"
  special          = true
}

resource "proxmox_virtual_environment_vm" "main" {
  tags = var.machine.tags
  name = var.machine.name

  started = var.machine.started
  on_boot = var.machine.on_boot

  agent {
    enabled = var.machine.enable_agent
  }

  node_name = var.node
  bios      = var.machine.bios

  cpu {
    cores        = var.spec.cpu.cores
    architecture = var.spec.cpu.architecture
    flags        = var.spec.cpu.flags
    hotplugged   = var.spec.cpu.hotplugged
    type         = var.spec.cpu.type
  }

  scsi_hardware = var.spec.scsi_hardware

  disk {
    cache        = var.spec.disk.cache
    datastore_id = var.spec.disk.datastore_id
    interface    = var.spec.disk.interface
    file_id      = var.spec.disk.file_id
    iothread     = var.spec.disk.iothread
    discard      = var.spec.disk.discard
  }

  network_device {
    bridge = var.spec.network.bridge
  }

  dynamic "tpm_state" {
    for_each = var.machine.tpm != null ? var.machine.tpm : {}

    content {
      version      = tpm_state.value.version
      datastore_id = tpm_state.value.datastore_id
    }
  }

  dynamic "initialization" {
    for_each = var.spec.initialization != null ? [var.spec.initialization] : []

    content {
      ip_config {
        ipv4 {
          address = initialization.value.ip_config.ipv4.address
          gateway = initialization.value.ip_config.ipv4.gateway
        }
      }
      user_account {
        keys     = initialization.value.user_account.keys
        password = initialization.value.user_account.password
        username = initialization.value.user_account.username
      }
      user_data_file_id = initialization.value.user_account != null ? null : initialization.value.user_data_file_id
    }
  }
}
