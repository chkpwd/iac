resource "gravity_dhcp_scope" "scopes" {
  for_each = {
    lan = {
      vlan_id = var.vlan_ids.lan
      default = true
    }
    iot = {
      vlan_id = var.vlan_ids.iot
      default = false
    }
    guest = {
      vlan_id = var.vlan_ids.guest
      default = false
    }
  }

  name        = each.key
  default     = each.value.default
  subnet_cidr = "172.16.${each.value.vlan_id}.0/24"

  ipam = {
    type        = "internal"
    range_start = "172.16.${each.value.vlan_id}.100"
    range_end   = "172.16.${each.value.vlan_id}.150"
  }

  option {
    tag_name = "router"
    value    = "172.16.${each.value.vlan_id}.1"
  }

  option {
    tag_name = "name_server"
    value    = "172.16.${each.value.vlan_id}.1"
    value64  = [base64encode("172.16.${each.value.vlan_id}.1")]
  }

  dns {
    zone   = gravity_dns_zone.main.name
    search = [gravity_dns_zone.main.name]
  }
}
