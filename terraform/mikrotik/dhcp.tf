resource "routeros_ip_dhcp_server_network" "networks" {
  for_each = var.networks

  address    = "10.0.${each.value.vlan_id}.0/24"
  gateway    = "10.0.${each.value.vlan_id}.1"
  dns_server = [var.dns_ip]
  domain     = var.domain
  comment    = each.key
}

resource "routeros_ip_pool" "pool" {
  for_each = var.networks

  name   = each.key
  ranges = ["10.0.${each.value.vlan_id}.50-10.0.${each.value.vlan_id}.100"]
}

resource "routeros_ip_dhcp_server" "servers" {
  for_each = var.networks

  name         = each.key
  interface    = each.value.interface
  address_pool = routeros_ip_pool.pool[each.key].name
  lease_time   = "8h"
}

locals {
  leases_json = jsondecode(file("${path.root}/leases.json"))

  all_leases = flatten([
    for server, leases in local.leases_json : [
      for lease in leases : merge(lease, { server = server })
    ]
  ])
}

resource "routeros_ip_dhcp_server_lease" "leases" {
  for_each = {
    for record in local.all_leases : "${record.server}-${record.name}" => {
      name    = record.name
      address = record.address
      mac     = record.mac
      server  = record.server
    }
  }

  address     = each.value.address
  mac_address = each.value.mac
  comment     = each.value.name
  server      = each.value.server
}
