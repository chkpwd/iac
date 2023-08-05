# manage a DNS rewrite rule
resource "adguard_rewrite" "infra" {
  # Iterate over the records
  for_each    = {
    for record in jsondecode(file("${path.root}/template/infra.json")) : record.domain => record
  }

  # Mapped values in json
  domain = each.value.domain
  answer = each.value.answer

}