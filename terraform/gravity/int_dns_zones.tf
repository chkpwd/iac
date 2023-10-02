resource "gravity_dns_zone" "main" {
  name = "local.chkpwd.com."
  authoritative = true
  handlers = [
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
    {
      type = "forward_blocky",
      to   = "8.8.8.8",
      blocklists = "https://adaway.org/hosts.txt",
    },
  ]
}

resource "gravity_dns_zone" "k8s_gateway" {
  name = "k8s.chkpwd.com."
  handlers = [
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
    {
      type = "forward_ip",
      to   = "172.16.16.206",
      # Cache queries and their responses in etcd for 3600s
      cache_ttl = "3600"
    },
  ]
}

resource "gravity_dns_zone" "forward" {
  # Root zone, will be used for all queries that don't match other zones
  name = "."
  handlers = [
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
    {
      type = "forward_ip",
      to   = "1.1.1.1,8.8.8.8",
      # Cache queries and their responses in etcd for 3600s
      cache_ttl = "3600"
    },
  ]
}