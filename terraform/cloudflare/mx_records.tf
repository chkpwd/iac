resource "cloudflare_record" "cloudflare_email_main" {
  name    = "@"
  ttl     = 1
  type    = "MX"
  priority = 89
  value   = "route1.mx.cloudflare.net"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "cloudflare_email_secondary" {
  name    = "@"
  ttl     = 1
  type    = "MX"
  priority = 98
  value   = "route2.mx.cloudflare.net"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "cloudflare_email_ternary" {
  name    = "@"
  ttl     = 1
  type    = "MX"
  priority = 87
  value   = "route3.mx.cloudflare.net"
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}