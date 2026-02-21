resource "routeros_interface_bridge" "bridge" {
  name              = "bridge"
  comment           = "LAN bridge"
  admin_mac         = "04:F4:1C:B6:6A:A7"
  vlan_filtering    = true
  frame_types       = "admit-all"
  pvid              = 1
  ingress_filtering = false
  mvrp              = false
}

resource "routeros_interface_bridge_port" "bridge_ports" {
  for_each = toset([
    "ether2",
    "ether3",
    "ether4",
    "ether5",
    "ether6",
    "ether7",
    "ether8",
    "sfp-sfpplus1"
  ])

  bridge    = routeros_interface_bridge.bridge.name
  interface = each.key
  pvid      = 1
}

resource "routeros_interface_vlan" "vlans" {
  for_each = {
    for name, net in var.networks :
    name => net if name != "lan"
  }

  interface = routeros_interface_bridge.bridge.name
  name      = each.key
  vlan_id   = each.value.vlan_id
}

resource "routeros_interface_bridge_vlan" "tagged" {
  for_each = {
    for name, net in var.networks :
    name => net if name != "lan"
  }

  comment  = each.key
  bridge   = routeros_interface_bridge.bridge.name
  vlan_ids = [each.value.vlan_id]
  tagged   = ["bridge", "ether2"]
}

resource "routeros_interface_list" "wan" { name = "WAN" }

resource "routeros_interface_list" "lan" { name = "LAN" }

resource "routeros_interface_list_member" "wan" {
  interface = "ether1"
  list      = routeros_interface_list.wan.name
}

resource "routeros_interface_list_member" "lan_bridge" {
  interface = routeros_interface_bridge.bridge.name
  list      = routeros_interface_list.lan.name
}

resource "routeros_ip_address" "lan" {
  interface = "bridge"
  address   = "10.0.${var.networks.lan.vlan_id}.1/24"
  network   = "10.0.${var.networks.lan.vlan_id}.0"
  comment   = "LAN"
}

resource "routeros_ip_address" "iot" {
  interface = "iot"
  address   = "10.0.${var.networks.iot.vlan_id}.1/24"
  network   = "10.0.${var.networks.iot.vlan_id}.0"
  comment   = "VLAN ${var.networks.iot.vlan_id}"
}

resource "routeros_ip_address" "guest" {
  interface = "guest"
  address   = "10.0.${var.networks.guest.vlan_id}.1/24"
  network   = "10.0.${var.networks.guest.vlan_id}.0"
  comment   = "VLAN ${var.networks.guest.vlan_id}"
}

resource "routeros_ip_dhcp_client" "wan" {
  interface = "ether1"
}
