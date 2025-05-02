
resource "proxmox_virtual_environment_vm" "ollama" {
  name      = "ai-inference-01"
  node_name = "pve-srv-01"
  vm_id     = 505
  on_boot   = true

  tags = ["ai", "server", "terraform"]

  machine = "q35"

  agent {
    enabled = true
  }

  # use ACPI
  stop_on_destroy = false

  operating_system {
    type = "l26" # Linux 2.6
  }

  cpu {
    cores = 2
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
}
