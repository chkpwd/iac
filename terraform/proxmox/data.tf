data "proxmox_virtual_environment_dns" "main" {
  node_name = var.main_node
}

data "proxmox_virtual_environment_datastores" "main" {
  node_name = var.main_node
}
