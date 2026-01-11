resource "gravity_dns_zone" "root" {
  name          = "."
  authoritative = false
  default_ttl   = 86400
  handler_configs = jsonencode([
    {
      cache_ttl = 3600
      to        = ["8.8.8.8:53"]
      type      = "forward_blocky"
      allowlists = [
        "s.youtube.com",
      ]
    },
  ])
}

resource "gravity_dns_zone" "chkpwd" { # chkpwd.com
  name          = var.zone
  default_ttl   = 3600
  authoritative = false
  handler_configs = jsonencode([
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
    {
      to   = ["8.8.8.8:53"]
      type = "forward_ip"
    },
  ])
}

resource "gravity_dns_zone" "chkpwd-rev" {
  name          = "0.10.in-addr.arpa."
  default_ttl   = 3600
  authoritative = true
  handler_configs = jsonencode([
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
  ])
}

resource "gravity_dns_record" "private_gateway" {
  zone     = gravity_dns_zone.chkpwd.name
  hostname = "gateway"
  uid      = var.default_uid
  data     = "10.0.10.30"
  type     = "A"
}

resource "gravity_dns_record" "traefik" {
  zone     = gravity_dns_zone.chkpwd.name
  hostname = "traefik"
  uid      = var.default_uid
  data     = "10.0.10.4"
  type     = "A"
}

resource "gravity_dns_record" "unifi" {
  zone     = gravity_dns_zone.chkpwd.name
  hostname = "unifi"
  uid      = var.default_uid
  data     = "10.0.10.33"
  type     = "A"
}

# Create a new zone for OpenShift
resource "gravity_dns_zone" "ocp_sno" {
  name          = "sno.chkpwd.com."
  authoritative = true
  handler_configs = jsonencode([
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
  ])
}

resource "gravity_dns_record" "sno-ocp-api" {
  zone     = gravity_dns_zone.ocp_sno.name
  hostname = "api"
  uid      = var.default_uid
  data     = "10.0.10.55"
  type     = "A"
}

resource "gravity_dns_record" "sno-ocp-api-int" {
  zone     = gravity_dns_zone.ocp_sno.name
  hostname = "api-int"
  uid      = var.default_uid
  data     = "10.0.10.55"
  type     = "A"
}

resource "gravity_dns_record" "sno-ocp-wildcard" {
  zone     = gravity_dns_zone.ocp_sno.name
  hostname = "*.apps"
  uid      = var.default_uid
  data     = "10.0.10.55"
  type     = "A"
}

locals {
  records_json  = jsondecode(file("${path.root}/records.json"))
  lan_records   = local.records_json.lan
  guest_records = local.records_json.guest
  iot_records   = local.records_json.iot
}

resource "gravity_dns_record" "lan" {
  for_each = {
    for record in local.lan_records : record.hostname => {
      hostname = record.hostname
      data     = record.data
      type     = record.type
    }
  }

  zone     = gravity_dns_zone.chkpwd.name
  hostname = each.value.hostname
  uid      = var.default_uid
  data     = each.value.data
  type     = each.value.type
}

resource "gravity_dns_record" "guest" {
  for_each = {
    for record in local.guest_records : record.hostname => {
      hostname = record.hostname
      data     = record.data
      type     = record.type
    }
  }

  zone     = gravity_dns_zone.chkpwd.name
  hostname = each.value.hostname
  uid      = var.default_uid
  data     = each.value.data
  type     = each.value.type
}

resource "gravity_dns_record" "iot" {
  for_each = {
    for record in local.iot_records : record.hostname => {
      hostname = record.hostname
      data     = record.data
      type     = record.type
    }
  }

  zone     = gravity_dns_zone.chkpwd.name
  hostname = each.value.hostname
  uid      = var.default_uid
  data     = each.value.data
  type     = each.value.type
}
