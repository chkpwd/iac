resource "cloudflare_record" "zone_a_record" {
  name    = "chkpwd.com"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.sops_file.cloudflare-secrets.data["public_address"]
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}

resource "cloudflare_record" "www_a_record" {
  name    = "www"
  proxied = true
  ttl     = 1
  type    = "A"
  value   = data.sops_file.cloudflare-secrets.data["public_address"]
  zone_id = data.sops_file.cloudflare-secrets.data["cloudflare_zone_id"]
}
