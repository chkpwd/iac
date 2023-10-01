resource "opnsense_unbound_host_alias" "kubernetes" {
  depends_on = [ opnsense_unbound_host_override.kubernetes ]
  override = opnsense_unbound_host_override.kubernetes["ingress"].id

  for_each    = {
    for record in local.kubernetes_cname : element(split(".", record.data), 0) => {
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

resource "opnsense_unbound_host_alias" "external" {
  depends_on = [ opnsense_unbound_host_override.external ]
  override = opnsense_unbound_host_override.external["router"].id

  for_each    = {
    for record in local.external_cname : element(split(".", record.data), 0) => {
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
