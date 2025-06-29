resource "proxmox_virtual_environment_vm" "ollama" {
  name      = "ai-inference-01"
  node_name = "pve-srv-01"
  vm_id     = 505
  on_boot   = true

  tags            = ["ai", "server", "terraform"]
  machine         = "q35"
  stop_on_destroy = false # use ACPI

  serial_device {}
  agent { enabled = true }

  operating_system { type = "l26" } # Linux 2.6

  cpu {
    cores = 4
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = 4096
    floating  = 4096 # ballooning
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

resource "proxmox_virtual_environment_vm" "gravity-dns-02" {
  name      = "gravity-dns-02"
  node_name = "pve-srv-01"
  vm_id     = 300
  on_boot   = true

  tags            = ["dns", "server", "terraform"]
  machine         = "q35"
  stop_on_destroy = false # use ACPI

  serial_device {}
  agent { enabled = true }

  operating_system { type = "l26" } # Linux 2.6
  cpu {
    cores = 1
    type  = "x86-64-v2-AES"
  }

  memory {
    dedicated = 1024
    floating  = 1024 # ballooning
  }

  initialization {
    ip_config {
      ipv4 {
        address = "10.0.10.7/24"
        gateway = "10.0.10.1"
      }
    }

    user_data_file_id = proxmox_virtual_environment_file.common_cloud_init.id
    meta_data_file_id = proxmox_virtual_environment_file.gravity_dns_meta_data.id
  }

  network_device { bridge = "vmbr0" }

  disk {
    datastore_id = "prod-nvme"
    file_id      = proxmox_virtual_environment_download_file.debian_trixie_qcow2_generic.id
    interface    = "virtio0"
    iothread     = true
    discard      = "on"
    size         = 10
  }

  lifecycle {
    ignore_changes = [
      initialization[0].user_data_file_id,
      initialization[0].meta_data_file_id
    ]
  }
}
