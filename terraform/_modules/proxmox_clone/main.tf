resource "random_password" "main" {
  length           = 16
  override_special = "_%@"
  special          = true
}

resource "proxmox_virtual_environment_vm" "main" {
  tags        = var.machine.tags
  name        = var.machine.name

  node_name = var.node
  vm_id     = var.machine.id

  clone {
    vm_id = var.clone.vm_id
    full = var.clone.full
    datastore_id = var.clone.datastore_id
    node_name = var.clone.node_name
    retries = var.clone.retries
  }

  bios = var.machine.bios

  cpu {
    cores = var.spec.cpu.cores
    architecture = var.spec.cpu.architecture
    flags = var.spec.cpu.flags
    hotplugged = var.spec.cpu.hotplugged
    type = var.spec.cpu.type
  }

  disk {
    cache        = var.spec.disk.cache
    datastore_id = var.spec.disk.datastore_id
    interface    = var.spec.disk.interface
  }

  network_device {
    bridge = var.spec.network.bridge
  }

  initialization {
    ip_config {
      ipv4 {
        address = "dhcp"
      }
    }

    # user_account {
    #   keys     = [trimspace(tls_private_key.ubuntu_vm_key.public_key_openssh)]
    #   password = random_password.ubuntu_vm_password.result
    #   username = "ubuntu"
    # }

    # user_data_file_id = proxmox_virtual_environment_file.cloud_config.id
  }

  operating_system {
    type = "l26"
  }

  dynamic "tpm_state" {
    for_each = null != var.machine.tpm ? var.machine.tpm : {}

    content {
      version = var.machine.tpm.version
      datastore_id = var.machine.tpm.datastore_id
    }
  }

  # serial_device {}
}
