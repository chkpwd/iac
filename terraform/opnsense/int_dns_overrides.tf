resource "opnsense_unbound_host_override" "infra" {
  for_each = {
    for record in local.infra_a : element(split(".", record.data), 0) => {
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

resource "opnsense_unbound_host_override" "kubernetes" {
  for_each = {
    for record in local.kubernetes_a : element(split(".", record.data), 0) => {
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

resource "opnsense_unbound_host_override" "external" {
  for_each = {
    for record in local.external_a : element(split(".", record.data), 0) => {
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