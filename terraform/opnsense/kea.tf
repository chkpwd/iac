resource "opnsense_kea_subnet" "lan" {
  subnet       = "172.16.16.0/24"
  description  = "lan"
  auto_collect = false
  pools        = ["172.16.16.100-172.16.16.150"]

  routers = ["172.16.16.1"]

  dns_servers = ["172.16.16.4"]

  domain_name = "chkpwd.com"

  domain_search = ["chkpwd.com"]
}

resource "opnsense_kea_subnet" "subnets" {
  for_each = {
    iot = {
      vlan_id = var.vlan_ids.iot
    }
    guest = {
      vlan_id = var.vlan_ids.guest
    }
  }

  subnet       = "10.0.${each.value.vlan_id}.0/24"
  description  = each.key
  auto_collect = false
  pools        = ["10.0.${each.value.vlan_id}.100-10.0.${each.value.vlan_id}.150"]

  routers = ["10.0.${each.value.vlan_id}.1"]

  dns_servers = ["172.16.16.4"]

  domain_name = "chkpwd.com"

  domain_search = ["chkpwd.com"]
}

locals {
  # Get JSON for internal, kubernetes, and external configurations
  main               = jsondecode(file("${path.root}/reservations.json"))
  lan_reservations   = local.main.lan
  iot_reservations   = local.main.iot_vlan
  guest_reservations = local.main.guest_vlan
}

resource "opnsense_kea_reservation" "guest" {
  for_each = {
    for record in local.guest_reservations : record.name => {
      name    = record.name
      address = record.address
      mac     = record.mac
    }
  }

  subnet_id = opnsense_kea_subnet.subnets["guest"].id

  ip_address  = each.value.address
  mac_address = each.value.mac

  hostname = each.value.name

  description = each.value.name
}

resource "opnsense_kea_reservation" "iot" {
  for_each = {
    for record in local.iot_reservations : record.name => {
      name    = record.name
      address = record.address
      mac     = record.mac
    }
  }

  subnet_id = opnsense_kea_subnet.subnets["iot"].id

  ip_address  = each.value.address
  mac_address = each.value.mac

  hostname = each.value.name

  description = each.value.name
}

resource "opnsense_kea_reservation" "lan" {
  for_each = {
    for record in local.lan_reservations : record.name => {
      name    = record.name
      address = record.address
      mac     = record.mac
    }
  }

  subnet_id = opnsense_kea_subnet.lan.id

  ip_address  = each.value.address
  mac_address = each.value.mac

  hostname = each.value.name

  description = each.value.name
}
