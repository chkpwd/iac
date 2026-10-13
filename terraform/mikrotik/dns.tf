resource "routeros_dns" "dns-server" {
  allow_remote_requests = true
  servers               = ["1.1.1.1", "8.8.8.8"]
}

# Static records migrated off gravity. External-DNS (txt registry, owner
# "mikrotik") only touches records it created for k8s Gateway/CRD sources, so
# these Terraform-managed entries coexist safely.
locals {
  dns_records = jsondecode(file("${path.root}/dns_records.json"))
}

resource "routeros_ip_dns_record" "static" {
  for_each = { for record in local.dns_records : record.name => record }

  name            = each.value.name
  type            = each.value.type
  ttl             = "1h"
  comment         = "Managed by Terraform"
  address         = each.value.type == "A" ? each.value.value : null
  cname           = each.value.type == "CNAME" ? each.value.value : null
  match_subdomain = try(each.value.match_subdomain, false)
}
