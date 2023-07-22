resource "unbound_dns_record" "main" {
  for_each    = {
    for record in jsondecode(file("${path.root}/files/internal_dns.json")) :
    record.name => {
      name     = record.name
      proxy    = record.type == "CNAME" && substr(record.data, -1, 1) != "." ? "${record.data}." : record.data
      type     = record.type
      uid      = contains(keys(record), "uid") ? record.uid : "0"
    }
  }
  enabled     = each.value.enable
  hostname    = each.value.name
  domain      = each.value.domain
}

resource "gravity_dns_record" "main" {
  for_each    = {
    for record in jsondecode(file("${path.root}/files/internal_dns.json")) :
    record.name => {
      name     = record.name
      proxy    = record.type == "CNAME" && substr(record.data, -1, 1) != "." ? "${record.data}." : record.data
      type     = record.type
      uid      = contains(keys(record), "uid") ? record.uid : "0"
    }
  }
  zone        = gravity_dns_zone.name
  hostname    = each.value.name
  uid         = each.value.uid
  data        = each.value.data
  type        = each.value.type
}