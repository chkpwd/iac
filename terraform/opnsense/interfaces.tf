resource "opnsense_interfaces_vlan" "vlan01" {
  device = "vlan01"
  parent = "em0"
  tag = 10
  priority = 0
  description = "IOT VLAN"
}

resource "opnsense_interfaces_vlan" "vlan02" {
  device = "vlan02"
  parent = "em0"
  tag = 20
  priority = 0
  description = "LAB VLAN"
}
