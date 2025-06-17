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
      type = "forward_ip",
      to   = ["1.1.1.1", "8.8.8.8"],
      # Cache queries and their responses in etcd for 3600s
      cache_ttl = 3600
    },
  ])
}

resource "gravity_dns_record" "private_gateway" {
  zone     = gravity_dns_zone.main.name
  hostname = "@"
  uid      = "0"
  data     = "172.16.16.30"
  type     = "A"
}

resource "gravity_dns_record" "public_gateway" {
  zone     = gravity_dns_zone.main.name
  hostname = "@"
  uid      = "0"
  data     = "172.16.16.31"
  type     = "A"
}
