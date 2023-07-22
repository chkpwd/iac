resource "opnsense_unbound_host_override" "main" {
  for_each = {
    for record in local.type_a : element(split(".", record.data), 0) => {
      enable   = record.enable
      name     = element(split(".", record.data), 0)
      domain   = join(".", slice(split(".", record.data), 1, length(split(".", record.data))))
      address  = record.address
    }
  }

  enabled     = each.value.enable
  hostname    = each.value.name
  domain      = each.value.domain
  server      = each.value.address
}