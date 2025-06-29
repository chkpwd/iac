resource "opnsense_kea_subnet" "subnets" {
  for_each = {
    iot = {
      interface_id = var.interfaces.iot
    }
    guest = {
      interface_id = var.interfaces.guest
    }
    lan = {
      interface_id = var.interfaces.lan
    }
  }

  subnet       = "10.0.${each.value.interface_id}.0/24"
  description  = each.key
  auto_collect = false
  pools        = ["10.0.${each.value.interface_id}.100-10.0.${each.value.interface_id}.150"]

  routers       = ["10.0.${each.value.interface_id}.1"]
  dns_servers   = ["10.0.10.4"]
  domain_name   = "chkpwd.com"
  domain_search = ["chkpwd.com"]
}

locals {
  leases_json  = jsondecode(file("${path.root}/leases.json"))
  lan_leases   = local.leases_json.lan
  iot_leases   = local.leases_json.iot
  guest_leases = local.leases_json.guest
  # mgmt_leases  = local.leases_json.mgmt
}

resource "opnsense_kea_reservation" "guest" {
  for_each = {
    for record in local.guest_leases : record.name => {
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
    for record in local.iot_leases : record.name => {
      name    = record.name
      address = record.address
      mac     = record.mac
    }
  }

  subnet_id = opnsense_kea_subnet.subnets["iot"].id

  ip_address  = each.value.address
  mac_address = each.value.mac
  hostname    = each.value.name
  description = each.value.name
}

resource "opnsense_kea_reservation" "lan" {
  for_each = {
    for record in local.lan_leases : record.name => {
      name    = record.name
      address = record.address
      mac     = record.mac
    }
  }

  subnet_id   = opnsense_kea_subnet.subnets["lan"].id
  ip_address  = each.value.address
  mac_address = each.value.mac
  hostname    = each.value.name
  description = each.value.name
}
