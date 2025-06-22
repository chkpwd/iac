resource "gravity_dns_zone" "main" {
  name          = var.zone
  authoritative = true
  handler_configs = jsonencode([
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
    {
      type = "forward_blocky",
      to   = ["1.1.1.1"],
    },
  ])
}

resource "gravity_dns_zone" "main-rev" {
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

# resource "gravity_dns_record" "main-rev-device" {
#   zone     = gravity_dns_zone.main-rev.id
#   hostname = "${split(".", each.value)[3]}.${split(".", each.value)[2]}"
#   uid      = var.default_uid
#   data     = "${each.key}.${gravity_dns_zone.net-io.name}"
#   type     = "PTR"
#   for_each = gravity_dhcp_lease.lan_reservations
# }

resource "gravity_dns_zone" "forward" {
  # Root zone, will be used for all queries that don't match other zones
  name = "."
  handler_configs = jsonencode([
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
    {
      type      = "forward_ip",
      to        = ["1.1.1.1", "1.0.0.1"],
      cache_ttl = 3600
    },
  ])
}

resource "gravity_dns_record" "private_gateway" {
  zone     = gravity_dns_zone.main.name
  hostname = "@"
  uid      = var.default_uid
  data     = "172.16.16.30"
  type     = "A"
}

resource "gravity_dns_record" "unifi" {
  zone     = gravity_dns_zone.main.name
  hostname = "unifi.${gravity_dns_zone.main.name}"
  uid      = var.default_uid
  data     = "172.16.16.33"
  type     = "A"
}
