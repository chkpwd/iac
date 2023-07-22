resource "gravity_dns_zone" "main" {
  zone          = "local.chkpwd.com."
  authoritative = true
  handlers = [
    {
      type = "memory",
    },
    {
      type = "etcd",
    },
  ]
}