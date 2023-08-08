resource "gravity_dns_record" "main" {
  for_each    = {
    for record in jsondecode(file("${path.root}/files/internal_dns.json")) :
    record.name => {
      type     = record.type
      name     = record.name
      data     = record.type == "CNAME" && substr(record.data, -1, 1) != "." ? "${record.data}." : record.data
      uid      = contains(keys(record), "uid") ? record.uid : "0"
    }
  }
  zone        = gravity_dns_zone.main.name
  hostname    = each.value.name
  uid         = each.value.uid
  data        = each.value.data
  type        = each.value.type
}