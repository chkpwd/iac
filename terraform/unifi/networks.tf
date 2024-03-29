resource "unifi_network" "lab" {
  name    = "LAB"
  purpose = "vlan-only"

  vlan_id      = var.vlans["lab"]
  dhcp_enabled = false
  site         = var.site
}

resource "unifi_network" "iot" {
  name    = "IOT"
  purpose = "vlan-only"

  vlan_id      = var.vlans["iot"]
  dhcp_enabled = false
  site         = var.site
}
