resource "cloudflare_record" "main" {
  name    = "chkpwd.com"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.external.bws_lookup.result["infra-network-secrets_public_ip"]
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_record" "www_main" {
  name    = "www"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.external.bws_lookup.result["infra-network-secrets_public_ip"]
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_record" "uptime" {
  name    = "uptime.chkpwd.com"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.tfe_outputs.aws.values.ct-01-ec2_public_ip
  zone_id = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}
