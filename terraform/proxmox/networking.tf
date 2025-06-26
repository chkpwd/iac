resource "proxmox_virtual_environment_time" "main" {
  node_name = var.node
  time_zone = var.timezone
}

resource "proxmox_virtual_environment_dns" "main" {
  domain    = var.domain
  node_name = var.node
  servers   = var.dns_servers
}

resource "proxmox_virtual_environment_network_linux_bridge" "vmbr1" {
  node_name  = var.node
  name       = "vmbr1"
  vlan_aware = true

  ports = [
    "enp6s0"
  ]
}
