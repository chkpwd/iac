resource "gravity_dns_record" "infra_a_records" {
  for_each = {
    for record in local.infra_a : element(split(".", record.data), 0) => {
      name = element(split(".", record.data), 0)
      address  = record.address
      uid      = try(record.uid, null)
    }
  }
  zone         = gravity_dns_zone.main.name
  hostname     = each.value.name
  uid          = each.value.uid
  type         = "A"
  data         = each.value.address
}

resource "gravity_dns_record" "infra_cname_records" {
  for_each = {
    for record in local.infra_cname : element(split(".", record.data), 0) => {
      name = element(split(".", record.data), 0)
      address  = record.address
      uid      = try(record.uid, null)
    }
  }
  zone         = gravity_dns_zone.main.name
  hostname     = each.value.name
  uid          = each.value.uid
  type         = "CNAME"
  data         = each.value.address
}

resource "gravity_dns_record" "external_a_records" {
  for_each = {
    for record in local.external_a : element(split(".", record.data), 0) => {
      name = element(split(".", record.data), 0)
      address  = record.address
      uid      = try(record.uid, null)
    }
  }
  zone         = gravity_dns_zone.main.name
  hostname     = each.value.name
  uid          = each.value.uid
  type         = "A"
  data         = each.value.address
}

resource "gravity_dns_record" "external_cname_records" {
  for_each = {
    for record in local.external_cname : element(split(".", record.data), 0) => {
      name = element(split(".", record.data), 0)
      address  = record.address
      uid      = try(record.uid, null)
    }
  }
  zone         = gravity_dns_zone.main.name
  hostname     = each.value.name
  uid          = each.value.uid
  type         = "CNAME"
  data         = each.value.address
}

resource "gravity_dns_record" "kubernetes_a_records" {
  for_each = {
    for record in local.kubernetes_a : element(split(".", record.data), 0) => {
      name = element(split(".", record.data), 0)
      address  = record.address
      uid      = try(record.uid, null)
    }
  }
  zone         = gravity_dns_zone.main.name
  hostname     = each.value.name
  uid          = each.value.uid
  type         = "A"
  data         = each.value.address
}

resource "gravity_dns_record" "kubernetes_cname_records" {
  for_each = {
    for record in local.kubernetes_cname : element(split(".", record.data), 0) => {
      name = element(split(".", record.data), 0)
      address  = record.address
      uid      = try(record.uid, null)
    }
  }
  zone         = gravity_dns_zone.main.name
  hostname     = each.value.name
  uid          = each.value.uid
  type         = "CNAME"
  data         = each.value.address
}