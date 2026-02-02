resource "cloudflare_dns_record" "main" {
  name    = "chkpwd.com"
  proxied = true
  ttl     = 1
  type    = "A"
  content = data.external.bws_lookup.result["infra-network-secrets_public_ip"]
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_dns_record" "www_main" {
  name    = "www"
  proxied = true
  ttl     = 1
  type    = "A"
  content = data.external.bws_lookup.result["infra-network-secrets_public_ip"]
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_dns_record" "gatus" {
  name    = "gatus.chkpwd.com"
  proxied = true
  ttl     = 1
  type    = "A"
  content = data.tfe_outputs.aws.values.ct-01-ec2_public_ip
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_dns_record" "monitoring" {
  name    = data.external.bws_lookup.result["monitoring_a_record_name"]
  proxied = false
  ttl     = 1
  type    = "A"
  content = data.external.bws_lookup.result["infra-network-secrets_public_ip"]
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}
