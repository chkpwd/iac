resource "opnsense_interfaces_vlan" "vlan01" {
  device      = "vlan01"
  parent      = "em0"
  tag         = var.vlan_ids.guest
  priority    = 0
  description = "IOT"
}

resource "opnsense_interfaces_vlan" "vlan02" {
  device      = "vlan02"
  parent      = "em0"
  tag         = var.vlan_ids.iot
  priority    = 0
  description = "LAB"
}

resource "opnsense_interfaces_vlan" "vlan03" {
  device      = "vlan03"
  parent      = "em0"
  tag         = var.vlan_ids.mgmt
  priority    = 0
  description = "MANAGEMENT"
}
