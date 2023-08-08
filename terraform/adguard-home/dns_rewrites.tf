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

# manage a DNS rewrite rule for kubes
resource "adguard_rewrite" "kubes" {
  # Iterate over the records
  for_each    = {
    for record in jsondecode(file("${path.root}/template/kubes.json")) : record.domain => record
  }

  # Mapped values in json
  domain = each.value.domain
  answer = each.value.answer

}

# manage a DNS rewrite rule for traefik
resource "adguard_rewrite" "traefik" {
  # Iterate over the records
  for_each    = {
    for record in jsondecode(file("${path.root}/template/traefik.json")) : record.domain => record
  }

  # Mapped values in json
  domain = each.value.domain
  answer = each.value.answer

}