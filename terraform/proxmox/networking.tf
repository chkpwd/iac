resource "proxmox_virtual_environment_time" "main" {
  node_name = var.node
  time_zone = "America/New_York"
}

resource "proxmox_virtual_environment_dns" "main" {
  domain    = data.proxmox_virtual_environment_dns.main.domain
  node_name = data.proxmox_virtual_environment_dns.main.node_name

  servers = [
    "1.1.1.1",
    "1.0.0.1",
  ]
}

resource "proxmox_virtual_environment_network_linux_bridge" "vmbr1" {
  node_name  = var.node
  name       = "vmbr1"
  vlan_aware = true

  ports = [
    "enp6s0"
  ]
}
