resource "cloudflare_dns_record" "cloudflare_email_main" {
  name     = "@"
  ttl      = 1
  type     = "MX"
  priority = 89
  content  = "route1.mx.cloudflare.net"
  zone_id  = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_dns_record" "cloudflare_email_secondary" {
  name     = "@"
  ttl      = 1
  type     = "MX"
  priority = 98
  content  = "route2.mx.cloudflare.net"
  zone_id  = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}

resource "cloudflare_dns_record" "cloudflare_email_ternary" {
  name     = "@"
  ttl      = 1
  type     = "MX"
  priority = 87
  content  = "route3.mx.cloudflare.net"
  zone_id  = data.external.bws_lookup.result["cloudflare-dns-secrets_zone_id"]
}
