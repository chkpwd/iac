resource "macaddress" "main" {
  for_each = var.nodes_cfg
  prefix   = [188, 36, 17]
}

resource "proxmox_virtual_environment_vm" "ollama" {
  name      = var.nodes_cfg["ai-inference-01"].name
  node_name = "pve-srv-01"
  vm_id     = var.nodes_cfg["ai-inference-01"].vm_id
  on_boot   = true

  tags            = ["ai", "server", "terraform"]
  machine         = "q35"
  stop_on_destroy = false # use ACPI

  serial_device {}
  agent { enabled = true }

  operating_system { type = "l26" } # Linux 2.6

  cpu {
    cores = var.nodes_cfg["ai-inference-01"].cpus
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = var.nodes_cfg["ai-inference-01"].memory
    floating  = var.nodes_cfg["ai-inference-01"].memory # ballooning
  }

  initialization {
    ip_config {
      ipv4 {
        address = "dhcp"
      }
    }

    user_data_file_id = proxmox_virtual_environment_file.common_cloud_init.id
    meta_data_file_id = proxmox_virtual_environment_file.ollama_meta_data.id
  }

  network_device {
    bridge      = "vmbr0"
    mac_address = "BC:24:11:EA:6B:79"
  }

  disk {
    datastore_id = "prod-nvme"
    file_id      = proxmox_virtual_environment_download_file.debian_trixie_qcow2_generic.id
    interface    = "virtio0"
    iothread     = true
    discard      = "on"
    size         = 75
  }

  hostpci {
    mapping = "titan-x"
    device  = "hostpci0"
  }

  lifecycle {
    ignore_changes = [
      initialization[0].user_data_file_id,
      initialization[0].meta_data_file_id
    ]
  }
}

resource "proxmox_virtual_environment_vm" "openshift-tools" {
  name      = var.nodes_cfg["openshift-tools"].name
  node_name = "pve-srv-01"
  vm_id     = var.nodes_cfg["openshift-tools"].vm_id
  on_boot   = true

  tags            = ["openshift", "server", "terraform"]
  machine         = "q35"
  stop_on_destroy = false # use ACPI

  serial_device {}
  agent { enabled = true }

  operating_system { type = "l26" } # Linux 2.6
  cpu {
    cores = var.nodes_cfg["openshift-tools"].cpus
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = var.nodes_cfg["openshift-tools"].memory
    floating  = var.nodes_cfg["openshift-tools"].memory # ballooning
  }

  initialization {
    user_data_file_id = proxmox_virtual_environment_file.common_cloud_init.id
    meta_data_file_id = proxmox_virtual_environment_file.openshift-tools_meta_data.id
  }

  network_device {
    bridge      = "vmbr0"
    mac_address = macaddress.main["openshift-tools"].id
  }

  disk {
    datastore_id = "prod-nvme"
    file_id      = proxmox_virtual_environment_download_file.debian_trixie_qcow2_generic.id
    interface    = "virtio0"
    iothread     = true
    discard      = "on"
    size         = 100
  }

  lifecycle {
    ignore_changes = [
      initialization[0].user_data_file_id,
      initialization[0].meta_data_file_id
    ]
  }
}
