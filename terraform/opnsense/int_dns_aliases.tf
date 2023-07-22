resource "opnsense_unbound_host_alias" "main" {
  override = opnsense_unbound_host_override.main[each.key].id

  for_each    = {
    for record in local.type_cname : element(split(".", record.data), 0) => {
      enable   = record.enable
      name     = element(split(".", record.data), 0)
      domain   = join(".", slice(split(".", record.data), 1, length(split(".", record.data))))
      address  = record.address
    }
  }

  enabled     = each.value.enable
  hostname    = each.value.name
  domain      = each.value.domain
}
