resource "gravity_dns_zone" "root" {
  name          = "."
  authoritative = false
  default_ttl   = 86400
  handler_configs = jsonencode([
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
    {
      cache_ttl = 3600
      to        = ["8.8.8.8:53"]
      type      = "forward_blocky"
      allowlists = [
        "s.youtube.com",
      ]
    },
    {
      to   = ["8.8.8.8:53"]
      type = "forward_ip"
    },
  ])
}

resource "gravity_dns_zone" "main" {
  name          = var.zone
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

resource "gravity_dns_zone" "temp" {
  name          = "16.172.in-addr.arpa."
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

resource "gravity_dns_zone" "main-rev" {
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
  zone     = gravity_dns_zone.main.name
  hostname = "gateway"
  uid      = var.default_uid
  data     = "10.0.10.30"
  type     = "A"
}

resource "gravity_dns_record" "public_gateway" {
  zone     = gravity_dns_zone.main.name
  hostname = "*"
  uid      = var.default_uid
  data     = "10.0.10.31"
  type     = "A"
}

resource "gravity_dns_record" "traefik" {
  zone     = gravity_dns_zone.main.name
  hostname = "traefik"
  uid      = var.default_uid
  data     = "10.0.10.4"
  type     = "A"
}

resource "gravity_dns_record" "unifi" {
  zone     = gravity_dns_zone.main.name
  hostname = "unifi"
  uid      = var.default_uid
  data     = "10.0.10.33"
  type     = "A"
}

locals {
  records_json = jsondecode(file("${path.root}/records.json"))
  lan_records  = local.records_json.lan
}

resource "gravity_dns_record" "lan" {
  for_each = {
    for record in local.lan_records : record.hostname => {
      hostname = record.hostname
      data     = record.data
      type     = record.type
    }
  }

  zone     = gravity_dns_zone.main.name
  hostname = each.value.hostname
  uid      = var.default_uid
  data     = each.value.data
  type     = each.value.type
}
