resource "unifi_network" "iot" {
  name    = "IoT"
  purpose = "vlan-only"

  vlan_id      = var.vlans["iot"]
  dhcp_enabled = false
  site         = var.site
}

resource "unifi_network" "guest" {
  name    = "Guest"
  purpose = "vlan-only"

  vlan_id      = var.vlans["guest"]
  dhcp_enabled = false
  site         = var.site
}
